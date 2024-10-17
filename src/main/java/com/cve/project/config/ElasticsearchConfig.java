package com.cve.project.config;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import co.elastic.clients.transport.ElasticsearchTransport;

@Configuration
public class ElasticsearchConfig {
    @Value("${server.ssl.host}")
    private String host;

    @Value("${server.ssl.port}")
    private int port;

    @Value("${server.ssl.stream}")
    private String stream;

    @Value("${spring.elasticsearch.username}")
    private String username;

    @Value("${spring.elasticsearch.password}")
    private String password;

    @Value("${server.ssl.keystore.password}")
    private String keyStorePassword;

    @Value("${server.ssl.keystore.path}")
    private String keyStorePath;

    @Bean
    public RestClientTransport restClientTransport(RestClient restClient) {
        return new RestClientTransport(restClient, new JacksonJsonpMapper());
    }

    @Bean
    public ElasticsearchClient elasticsearchClient(RestClientTransport restClientTransport) {
        return new co.elastic.clients.elasticsearch.ElasticsearchClient(restClientTransport);
    }


    @Bean
    public RestClient restClient() throws Exception {
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        final SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(
                        getKeyStore(),
                        new TrustSelfSignedStrategy())
                .build();


        RestClient client = RestClient.builder(new HttpHost(host, port, stream))
                .setHttpClientConfigCallback(httpClientBuilder -> httpClientBuilder
                        .setDefaultCredentialsProvider(credentialsProvider)
                        .setSSLContext(sslContext)
                ).build();
        return client;
    }

    public KeyStore getKeyStore() throws Exception {
        FileInputStream keystore = new FileInputStream(new File(keyStorePath));
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(keystore, keyStorePassword.toCharArray());
        return keyStore;
    }

}