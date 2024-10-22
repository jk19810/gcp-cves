package com.cve.project.service;

import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CVEService {

	@Autowired
	private RestClient restClient;

	private static final Logger log = LoggerFactory.getLogger(CVEService.class);

	@Value("${elastic.query.search}")
	private String searchQueryTemplate;

	@Value("${elastic.query.version}")
	private String versionQuery;

	@Value("${elastic.query.version-artifact}")
	private String queryTemplateForVersionAndArtifact;

	@Value("${elastic.query.version-group}")
	private String queryTemplateForVersionAndGroup;

	@Value("${elastic.query.wildcard}")
	private String wildcardQuery;

	/**
	 * 
	 * @param index
	 * @param field
	 * @param keyword
	 * @return
	 */
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
			log.error("", e.getMessage());
			throw new RuntimeException(e.getMessage());
		} finally {
			elasticQuery = null;
		}
	}

	// get data related artifact, group and version
	/**
	 * 
	 * @param index
	 * @param keyword
	 * @return
	 */
	public Object wildcard(String index, String keyword) {
		String elasticQuery = new String(wildcardQuery);
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
			log.error("", e.getMessage());
			throw new RuntimeException(e.getMessage());
		} finally {
			elasticQuery = null;
		}

	}

	// get data by versions related
	public Object getCveByVersions(String index, String version) {
		String elasticQuery = new String(versionQuery);
		if (!version.endsWith("0")) {
			version = version.concat(".0");
		}

		elasticQuery = elasticQuery.replace("#version#", version);
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
			log.error("", e.getMessage());
			throw new RuntimeException(e.getMessage());
		} finally {
			elasticQuery = null;
		}
	}

	/**
	 * 
	 * @param index
	 * @param artifact
	 * @param version
	 * @return
	 */
	public Object getCveByArtifactAndVersions(String index, String artifact, String version) {
		String elasticQuery = new String(queryTemplateForVersionAndArtifact);
		if (!version.endsWith("0")) {
			version = version.concat(".0");
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
			log.error("", e.getMessage());
			throw new RuntimeException(e.getMessage());
		} finally {
			elasticQuery = null;
		}
	}

	/**
	 * 
	 * @param index
	 * @param group
	 * @param version
	 * @return
	 */
	public Object getCveByGroupAndVersions(String index, String group, String version) {
		String elasticQuery = new String(queryTemplateForVersionAndGroup);
		if (!version.endsWith("0")) {
			version = version.concat(".0");
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
			log.error("", e.getMessage());
			throw new RuntimeException(e.getMessage());
		} finally {
			elasticQuery = null;
		}
	}

}
