import requests
import os


os.makedirs('static/images', exist_ok=True)


url = 'https://yt3.googleusercontent.com/ytc/AIf8zZQTjNyVw0c7nEPOmAMSXUl-3mIaUZQQlKWLbQ=s900-c-k-c0x00ffffff-no-rj'


response = requests.get(url, stream=True)
if response.status_code == 200:
    with open('static/images/anand_logo.png', 'wb') as f:
        for chunk in response.iter_content(1024):
            f.write(chunk)
    print("Logo downloaded successfully!")
else:
    print(f"Failed to download logo: {response.status_code}")
