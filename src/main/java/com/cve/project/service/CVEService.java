package com.cve.project.service;


import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CVEService {

	@Autowired
	private RestClient restClient;
	
	@Value("${elastic.search.query}")
    private String searchQueryTemplate;

	@Value("${elastic.version.query}")
    private String queryTemplate;
	
	@Value("${elastic.version-artifact.query}")
    private String queryTemplateForVersionAndArtifact;
	
	public Object search(String index, String field, String keyword) {
		String elasticQuery = new String(searchQueryTemplate);
		elasticQuery = elasticQuery.replace("#field#", field);
		elasticQuery = elasticQuery.replace("#keyword#", keyword);
		
		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(elasticQuery);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}finally {
			elasticQuery=null;
		}
	}

	// get data related artifact, group and version
	public Object wildcard(String index, String keyword) {
		String versions = "versions";
		String artifact = "artifact";
		String group = "group";
		
		String jsonString = "{\n" +
			    "  \"query\": {\n" +
			    "    \"bool\": {\n" +
			    "      \"should\": [\n" +
			    "        {\n" +
			    "          \"nested\": {\n" +
			    "            \"path\": \"version_pairs\",\n" +
			    "            \"query\": {\n" +
			    "              \"bool\": {\n" +
			    "                \"must\": [\n" +
			    "                  {\n" +
			    "                    \"range\": {\n" +
			    "                      \"version_pairs.version_start\": {\n" +
			    "                        \"lte\": \"" + keyword + "\"\n" +
			    "                      }\n" +
			    "                    }\n" +
			    "                  },\n" +
			    "                  {\n" +
			    "                    \"range\": {\n" +
			    "                      \"version_pairs.version_end\": {\n" +
			    "                        \"gte\": \"" + keyword + "\"\n" +
			    "                      }\n" +
			    "                    }\n" +
			    "                  }\n" +
			    "                ]\n" +
			    "              }\n" +
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
	
	// get data by versions related
	public Object getCveByVersions(String index, String version) {

		String jsonString = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"version_pairs\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            {\n" +
                "              \"range\": {\n" +
                "                \"version_pairs.version_start\": {\n" +
                "                  \"lte\": \"" + version + "\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            {\n" +
                "              \"range\": {\n" +
                "                \"version_pairs.version_end\": {\n" +
                "                  \"gte\": \"" + version + "\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
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
	
	public Object getCveByArtifactAndVersions(String index, String artifact, String version) {
		
		String elasticQuery = new String(queryTemplateForVersionAndArtifact);
		if(!version.endsWith("0")) {
			version=version.concat(".0");
		}
		
		elasticQuery = elasticQuery.replace("#version#", version);
		elasticQuery = elasticQuery.replace("#artifact#", artifact);
		
		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(elasticQuery);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}finally {
			elasticQuery=null;
		}
	}
	
	public Object getCveByGroupAndVersions(String index, String group, String version) {
		String elasticQuery = new String(queryTemplate);
		if(!version.endsWith("0")) {
			version=version.concat(".0");
		}
		
		elasticQuery = elasticQuery.replace("#version#", version);
		elasticQuery = elasticQuery.replace("#group#", group);
		try {
			Request request = new Request("GET", "/" + index + "/_search");
			request.setJsonEntity(elasticQuery);
			Response response = restClient.performRequest(request);
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				return EntityUtils.toString(entity);
			}
			return "no content found!";
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}finally {
			elasticQuery=null;
		}
	}

}
