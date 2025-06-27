from datetime import datetime, timedelta, timezone

# Import SSL patch to disable certificate verification
import ssl_patch

import jwt
import jwt.algorithms
import streamlit as st  #all streamlit commands will be available through the "st" alias
import utils
from streamlit_feedback import streamlit_feedback

UTC=timezone.utc

# Init configuration
utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

st.set_page_config(page_title="Amazon Q Business Custom UI") #HTML title
st.title("Amazon Q Business Custom UI") #page title

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""


oauth2 = utils.configure_oauth_component()
if "token" not in st.session_state:
    # If not, show authorize button
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    result = oauth2.authorize_button("Connect with Cognito",scope="openid", pkce="S256", redirect_uri=redirect_uri)
    if result and "token" in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get("token")
        # Retrieve the Identity Center token
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(st.session_state.token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(tz=UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token["refresh_token"] # saving the long lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]
    if st.button("Refresh Cognito Token") :
        # If refresh token button is clicked or the token is expired, refresh the token
        token = oauth2.refresh_token(token, force=True)
        # Put the refresh token in the session state as it is not returned by Cognito
        token["refresh_token"] = refresh_token
        # Retrieve the Identity Center token

        st.session_state.token = token
        st.rerun()

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        # If the Identity Center token is expired, refresh the Identity Center token
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(
                st.session_state["idc_jwt_token"]["refreshToken"]
                )
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
                timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    col1, col2 = st.columns([1,1])

    with col1:
        st.write("Welcome: ", user_email)
    with col2:
        st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize the chat messages in the session state if it doesn't exist
    if "messages" not in st.session_state:
        st.session_state["messages"] = [{"role": "assistant", "content": "How can I help you?"}]

    if "conversationId" not in st.session_state:
        st.session_state["conversationId"] = ""

    if "parentMessageId" not in st.session_state:
        st.session_state["parentMessageId"] = ""

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    if "questions" not in st.session_state:
        st.session_state.questions = []

    if "answers" not in st.session_state:
        st.session_state.answers = []

    if "input" not in st.session_state:
        st.session_state.input = ""


    # Display the chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])


    # User-provided prompt
    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)


    # If the last message is from the user, generate a response from the Q_backend
    if st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(prompt,st.session_state["conversationId"],
                                                 st.session_state["parentMessageId"],
                                                 st.session_state["idc_jwt_token"]["idToken"])
                
                # Format the answer following Google Developer Documentation Style Guide
                answer = response["answer"]
                
                # Apply consistent sentence spacing (single space after periods)
                answer = answer.replace(".  ", ". ")
                
                # Format paragraphs with appropriate spacing
                # Google style recommends clear paragraph breaks for readability
                paragraphs = []
                current_paragraph = []
                
                for line in answer.split("\n"):
                    line = line.strip()
                    if not line:
                        if current_paragraph:
                            paragraphs.append(" ".join(current_paragraph))
                            current_paragraph = []
                    else:
                        # Handle list items according to Google style (no extra line breaks within lists)
                        if (line.startswith("- ") or line.startswith("* ") or 
                            (line[0].isdigit() and ". " in line[:5])):
                            # If we were building a paragraph, finish it
                            if current_paragraph:
                                paragraphs.append(" ".join(current_paragraph))
                                current_paragraph = []
                            # Add the list item directly
                            paragraphs.append(line)
                        else:
                            current_paragraph.append(line)
                
                # Add any remaining paragraph
                if current_paragraph:
                    paragraphs.append(" ".join(current_paragraph))
                
                # Join paragraphs with double line breaks for clarity
                answer = "\n\n".join(paragraphs)
                
                # Format code blocks with proper markdown syntax
                # Google style emphasizes proper code formatting
                import re
                code_block_pattern = r'```(.*?)```'
                answer = re.sub(code_block_pattern, r'```\1```', answer, flags=re.DOTALL)
                
                # Use consistent heading styles (Google prefers sentence case for headings)
                heading_pattern = r'(#+)\s+(.*)'
                def format_heading(match):
                    level, text = match.groups()
                    # Convert to sentence case (first letter capitalized, rest lowercase)
                    formatted_text = text[0].upper() + text[1:].lower() if text else ""
                    return f"{level} {formatted_text}"
                
                answer = re.sub(heading_pattern, format_heading, answer)
                
                # Use consistent terminology (Google style emphasizes consistency)
                key_terms = {
                    "vendor list": "vendor list",
                    "approved vendor list": "Approved Vendor List",
                    "deliverable": "deliverable",
                    "suppliers": "suppliers",
                    "equipment": "equipment"
                }
                
                # Apply consistent terminology with proper formatting
                for term, formatted_term in key_terms.items():
                    # Case-insensitive replacement with consistent formatting
                    pattern = re.compile(re.escape(term), re.IGNORECASE)
                    answer = pattern.sub(f"**{formatted_term}**", answer)
                
                # Format the references section according to Google style
                if "references" in response:
                    full_response = f"""{answer}\n\n---\n### References\n{response["references"]}"""
                else:
                    full_response = f"""{answer}\n\n---\nNo references available"""
                
                placeholder.markdown(full_response)
                st.session_state["conversationId"] = response["conversationId"]
                st.session_state["parentMessageId"] = response["parentMessageId"]


        st.session_state.messages.append({"role": "assistant", "content": full_response})
        feedback = streamlit_feedback(
            feedback_type="thumbs",
            optional_text_label="[Optional] Please provide an explanation",
        )