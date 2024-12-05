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

@Service
public class OSVService {
	@Autowired
	private RestClient restClient;

	private static final Logger log = LoggerFactory.getLogger(CVEService.class);
	
	@Value("${elastic.query.osv.keyword}")
	private String keywordQuery;
	
	@Value("${elastic.query.osv.count}")
	private String countQuery;

	
	public Object getOsvByKeywordCount(String index, String keyword) {
		String elasticQuery = new String(keywordQuery);
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
	
	public Object getOsvByCount(String index) {
		String elasticQuery = new String(countQuery);
		try {
			Request request = new Request("GET", "/" + index + "/_search?filter_path=aggregations");
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
