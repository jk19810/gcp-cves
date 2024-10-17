package com.cve.project.service;

import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CVEService {

	@Autowired
	private RestClient restClient;

	public Object search(String index, String field, String keyword) {
		String jsonString ="{\n" +
		        "  \"query\": {\n" +
		        "    \"bool\": {\n" +
		        "      \"should\": [\n" +
		        "        {\n" +
		        "          \"match\": {\n" +
		        "            \"" + field + "\": \"" + keyword + "\"\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"wildcard\": {\n" +
		        "            \"" + field + "\": {\n" +
		        "              \"value\": \"*" + keyword + "*\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        }\n" +
		        "      ]\n" +
		        "    }\n" +
		        "  }\n" +
		        "}";

		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(jsonString);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public Object wildcard(String index, String keyword) {
		String versions = "versions";
		String artifact = "artifact";
		String group = "group";
		
		String jsonString = "{\n" +
		        "  \"query\": {\n" +
		        "    \"bool\": {\n" +
		        "      \"should\": [\n" +
		        "        {\n" +
		        "          \"match\": {\n" +
		        "            \"" + versions + "\": \"" + keyword + "\"\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"wildcard\": {\n" +
		        "            \"" + versions + "\": {\n" +
		        "              \"value\": \"*" + keyword + "*\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"match\": {\n" +
		        "            \"" + artifact + "\": \"" + keyword + "\"\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"wildcard\": {\n" +
		        "            \"" + artifact + "\": {\n" +
		        "              \"value\": \"*" + keyword + "*\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"match\": {\n" +
		        "            \"" + group + "\": \"" + keyword + "\"\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"wildcard\": {\n" +
		        "            \"" + group + "\": {\n" +
		        "              \"value\": \"*" + keyword + "*\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        }\n" +
		        "      ]\n" +
		        "    }\n" +
		        "  }\n" +
		        "}";

		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(jsonString);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
		
	}
	
	public Object getByVersions(String index, String version) {
		String jsonString = "{\n" +
		        "  \"query\": {\n" +
		        "    \"bool\": {\n" +
		        "      \"must\": [\n" +
		        "        {\n" +
		        "          \"range\": {\n" +
		        "            \"versionStart\": {\n" +
		        "              \"lte\": \"" + version + "\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        },\n" +
		        "        {\n" +
		        "          \"range\": {\n" +
		        "            \"versionEnd\": {\n" +
		        "              \"gte\": \"" + version + "\"\n" +
		        "            }\n" +
		        "          }\n" +
		        "        }\n" +
		        "      ]\n" +
		        "    }\n" +
		        "  }\n" +
		        "}";

		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(jsonString);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
	}

}
