import boto3
import gspread
import logging
import traceback
from google.oauth2.credentials import Credentials
from botocore.exceptions import BotoCoreError, NoCredentialsError, ClientError

# Configuración de logging
logging.basicConfig(level=logging.INFO)

def get_secret(secret_name):
    try:
        client = boto3.client('secretsmanager', region_name='us-east-1')
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except (BotoCoreError, NoCredentialsError, ClientError) as e:
        logging.error(f"Error obteniendo secretos: {str(e)}")
        send_email("Error en AWS Secrets Manager", str(e))
        raise

def update_google_sheet():
    try:
        secrets = get_secret("my-google-secrets")
        creds = Credentials.from_authorized_user_info(secrets)
        client = gspread.authorize(creds)
        sheet = client.open("My GSheet").sheet1
        sheet.append_row(["Datetime", "Data"], value_input_option="RAW")
        logging.info("Google Sheet has been updated correctly.")
    except Exception as e:
        logging.error(f"Error actualizando Google Sheet: {str(e)}")
        send_email("Error en actualización de Google Sheet", str(e))
        raise

def send_email(subject, message):
    try:
        ses_client = boto3.client('ses', region_name='us-east-1')
        ses_client.send_email(
            Source='your-email@example.com',
            Destination={'ToAddresses': ['destination@example.com']},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': message}}
            }
        )
        logging.info("Email has been sent successfully.")
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error while sending email: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        update_google_sheet()
        send_email("Script execution complete", "The script has been executed successfully and Google Sheet has been updated accordingly.")
    except Exception as e:
        logging.error(f"Error in the overall execution: {traceback.format_exc()}")
