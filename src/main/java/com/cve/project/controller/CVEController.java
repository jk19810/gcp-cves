package com.cve.project.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.cve.project.service.CVEService;

@RestController
@RequestMapping("/api/cve")
public class CVEController {
	
	private final String INDEX_NAME = "test-cves";
	
	@Autowired
	private CVEService cveService;

	@GetMapping("/artifact/{artifact}")
	public ResponseEntity<?> getCVEByArtifact(@PathVariable("artifact") String artifact){
		Object object = cveService.search(INDEX_NAME,"artifact", artifact);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/group/{group}")
	public ResponseEntity<?> getCVEByGroup(@PathVariable("group") String group){
		Object object = cveService.search(INDEX_NAME,"group", group);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/versions/{versions}")
	public ResponseEntity<?> getCVEByVersion(@PathVariable("versions") String version){
		Object object = cveService.getByVersions(INDEX_NAME, version);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/{keyword}")
	public ResponseEntity<?> getCVEByMatchQuery(@PathVariable("keyword") String keyword){
		Object object = cveService.wildcard(INDEX_NAME, keyword);
		return ResponseEntity.ok(object);
	}
	
}
