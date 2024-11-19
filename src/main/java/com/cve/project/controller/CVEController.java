package com.cve.project.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
	
	@Value("${elastic.csv.index.name}")
	private String INDEX_NAME;
	
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
		Object object = cveService.getCveByVersions(INDEX_NAME, version);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/{keyword}")
	public ResponseEntity<?> getCVEByWildcardSearch(@PathVariable("keyword") String keyword){
		Object object = cveService.wildcard(INDEX_NAME, keyword);
		return ResponseEntity.ok(object);
	}
	
	
	@GetMapping("/byArtifactAndVersion")
	public ResponseEntity<?> getCVEByArtifactAndVersion(
			@RequestParam String artifact,
			@RequestParam String version){
		Object object = cveService.getCveByArtifactAndVersions(INDEX_NAME, artifact, version);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/byGroupAndVersion")
	public ResponseEntity<?> getCVEByGroupAndVersion(
			@RequestParam String group,
			@RequestParam String version){
		Object object = cveService.getCveByGroupAndVersions(INDEX_NAME, group, version);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/count")
	public ResponseEntity<?> getCount(){
		Object object = cveService.getCount(INDEX_NAME);
		return ResponseEntity.ok(object);
	}
	
	@GetMapping("/keyword/{keyword}")
	public ResponseEntity<?> getKeywordBasedData(@PathVariable("keyword") String keyword){
		Object object = cveService.getCVSDataBasedKeyword(INDEX_NAME, keyword);
		return ResponseEntity.ok(object);
	}
	
}
