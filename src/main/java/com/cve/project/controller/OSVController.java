package com.cve.project.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cve.project.service.OSVService;

@RestController
@RequestMapping("/api/osv")
public class OSVController {
	@Value("${elastic.osv.index.name}")
	private String INDEX_NAME;
	
	@Autowired
	private OSVService osvService;
	
	@GetMapping("/count")
	public ResponseEntity<?> getOscCount(){
		Object object = osvService.getOsvByCount(INDEX_NAME);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/{keyword}")
	public ResponseEntity<?> getOsvByKeyword(@PathVariable("keyword") String keyword){
		Object object = osvService.getOsvByKeywordCount(INDEX_NAME, keyword);
		return ResponseEntity.ok(object);
	}

	@GetMapping("/id/{keyword}")
	public ResponseEntity<?> getOsvById(@PathVariable("keyword") String keyword){
		Object object = osvService.getOsvById(INDEX_NAME, keyword);
		return ResponseEntity.ok(object);
	}
}
