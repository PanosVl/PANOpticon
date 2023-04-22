# PANOpticon
A centralized CTI tool. 

### What is PANOpticon
PANOpticon is a Django web application that collects CTI from various publicly available sources (NIST's NVD, CISA's KEV, FIRST.org, AlienVault OTX, ExploitDB) and stores them centrally, on a CVE basis.  
That information can then be used as part of the prioritization process of Vulnerability Management, allowing for CTI-informed decision making.  
The project was part of my thesis in LTU's 2 years Master's Program in Information Security.  

### Getting started
This project uses Docker containers to isolate itself from the host environment and thus it's fairly simple to get started.  
You need a working installation of Docker, and a `.docker_envfile` with all the required secrets in the babse directory of the project.  
The contents of the docker envfile, follow the below format: 
```
POSTGRES_HOST='db'
POSTGRES_DB='YOUR_DATABASE_NAME'
POSTGRES_USER='YOUR_POSTGRES_USERNAME'
POSTGRES_PASSWORD='A_SECURE_PASSWORD'
OTX_KEY='ALIENVAULT_OTX_API_KEY'
NVD_API_KEY='NVD_API_KEY'
ALLOWED_HOSTS = "localhost 127.0.0.1"
SERVER_NAME = "localhost"
```  

Once the above are set, you can start everythign by navigating into the project's base directory and running:  
`docker compose -f "docker-compose.yml" up -d --build`  
This will create panopticon's compose stack, consisting of:  
1. __app__ container, that runs the Django application
2. __db__ container, that runs the PostgresSQL database  

Django is available on port 8000 and Postgres on port 5432.  

  
  Once the application is running, you need to attach a shell to the app container, and create a super user for Django. This will be used to access the admin panel and be able to see the information gathered.  
  To do so, use the manage command _createsuperuser_ with `python manage.py createsuperuser` and follow the prompts.  

  ### Application Diagram
  The application is quite simple on its design, consisting of the Django application, that writes to a Postgres database. The complex part is the extraction of data from the various sources. The diagram that follows shows the sources used and an overview of the app.  
  ![architecture](https://user-images.githubusercontent.com/8208803/233793902-daaf8d90-a5dc-43cd-a83c-f88926f28896.png)
