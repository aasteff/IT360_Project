Steps for this to work.
1. install beauftifulsoup4 and requests
   
   sudo apt install beautifulsoup4
   sudo apt install requests
   
   note: if this does not work try the code below
   pip may need to be installed as well

   sudo apt install python3-pip
   pip install beautifulsoup4
   pip install request

2. Then make a director for your files
   
   mkdir beautifulsoup_scraping

3. then cd into that directory
   
   cd ~/beautifulsoup_scraping

4. create the files from above and add the code
   
   sudo nano ioc.py
   sudo nano save_images.py

5. run the code
   
   python3 ioc.py
   python3 save_images.py

6. follow instructions and the output will be saved to ioc_report.txt and the image whatever you named it. 


note: you need an account for virustotal so you can get a api key and you need to insert it into the ioc.py code.
