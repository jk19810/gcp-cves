**GCP CVE’S Project Setup from GitHub**

This document outlines the steps to clone and set up a project from GitHub on your system.

Prerequisites

Git: Make sure Git is installed on your system. If not, you can download it.

JDK: Java Development Kit (JDK) should be installed if the project uses Java. Java > = 17

Elasticsearch: You need access to an Elasticsearch instance (local or remote).

Elasticsearch Key File: truststore.jks file and it’s password that can generates by elasticsearch crt file.

We use openssl tool to convert crt file to jks file for Java Application connectivity.

Step-by-Step Guide

Cloning the Project

Go to the GitHub repository for this application.

Clone the repository to your machine:

 git@github.com:jk19810/gcp-cves.git

Navigate into the project directory:

Configuring Elasticsearch with Truststore

Create a Truststore (if not already available): If you don't already have a truststore file, you can create one using the keytool command, importing your Elasticsearch SSL certificate.

keytool -import -alias elastic -file <path-to-certificat.crt> -keystore truststore.jks

 This command will create a truststore.jks file with password.

Update application.properties or application.yml

In your Java application, you need to configure the connection to Elasticsearch using the truststore.

For Spring Boot applications, update the application.properties or application.yml file:

Include Truststore in the Classpath

Ensure the truststore.jks file is located in the src/main/resources/cert directory so that it is available in the classpath.

Build the Application and Run

Once the configurations are set, you can build the project and Running app port 8080

**Java Project Workflow**

The Elasticsearch API Java project is designed to retrieve data from an Elasticsearch instance via an API. The application interacts with Elasticsearch to perform data queries and exposes APIs 
that allow users to request specific data from the cluster.

Architecture

Elasticsearch Client: The application uses an Elasticsearch Java client to interact with the Elasticsearch cluster. This client connects to Elasticsearch via REST API and executes various queries

API Layer: The application exposes RESTful endpoints that allow users to interact with the Elasticsearch data via HTTP requests. These endpoints handle data queries and responses.

Truststore/SSL Configuration: To securely communicate with Elasticsearch (when using HTTPS), the application leverages a truststore that contains SSL certificates.

**Process Flow - Data Retrieval from Elasticsearch**

API Request: A user sends a request to the application’s REST API to fetch data from Elasticsearch. The request is typically made to an endpoint such as /api/cve/**.

Elasticsearch Query Execution: The API layer receives the request and triggers a query to the Elasticsearch cluster. The query may be a basic search, or a more complex query, depending on the request: 

The query is executed using the Elasticsearch Java client

The client connects to the Elasticsearch cluster using the host, port, and credentials configured in the application’s properties file. If SSL is used, the client authenticates via the provided truststore.

Data Fetching: Elasticsearch processes the query and returns the results, which typically include documents, IDs, and metadata that match the query criteria.

Response: The fetched data is processed and formatted into a JSON response. The application then sends this response back to the API consumer (e.g., Postman, browser, or another service).

**API Usage**

We can also implement Swagger OpenAPI	

url for swagger – localhost:8080//swagger-ui/index.html

The application exposes an API that retrieves data from Elasticsearch. Below are the endpoints and their usage:

GET Data from Elasticsearch based on group, artifact and versions

Endpoint: /api/cve/{keyword}

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the query you specify.

GET Data from Elasticsearch based on artifact

Endpoint: /api/cve/artifact /{keyword}

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the artifact related.

GET Data from Elasticsearch based on group

Endpoint: /api/cve/group /{keyword}

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the group related.

GET Data from Elasticsearch based on version

Endpoint: /api/cve/version /{keyword} 

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the version related.

GET Data from Elasticsearch based on artifact and version

Endpoint: /api/cve/byArtifactAndVersion?group=<>&version=<>

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the artifact and version related.

GET Data from Elasticsearch based on group and version

Endpoint: /api/cve/byGroupAndVersion?group=<>&version=<>

Method: GET

Description: This endpoint fetches data from the Elasticsearch cluster based on the group and version related
