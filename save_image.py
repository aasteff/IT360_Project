import requests

# Ask the user for the image URL and filename
image_url = input("Enter the full image URL: ").strip()
filename = input("Enter the filename to save it as (e.g., image.jpg): ").strip()

# Download and save the image
response = requests.get(image_url)

if response.status_code == 200:
    with open(filename, 'wb') as f:
        f.write(response.content)
    print(f"✅ Image saved as '{filename}'")
else:
    print(f"❌ Failed to download image. Status code: {response.status_code}")
