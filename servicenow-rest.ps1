function servicenow-header {
	Param(
			[Parameter(Mandatory=$true)][System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$methodtype
		)
			if($script:debug){
				write-host "DEBUG: Building Header:" -foreground "green"
				write-host "DEBUG:" $credential
				write-host "DEBUG:" $methodtype
			}
			$headerobject = New-Object System.Object
			$user = $credential.GetNetworkCredential().username
			$pass = $credential.GetNetworkCredential().password
			$secpass = ConvertTo-SecureString -AsPlainText -Force -String $pass
			$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
			$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$header.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
			write-host "DEBUG: Added Authorization header"
			$methodtype = $($methodtype.toUpper())

			#write-host $methodtype
			if($methodtype -eq "GET"){
				$header.Add('Accept','application/json')
				write-host "DEBUG: Added Accept header"
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "PATCH"){
				$header.Add('Content-Type','application/json')
				write-host "DEBUG: Added Content-type header"
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "PUT"){
				$header.Add('Content-Type','application/json')
				write-host "DEBUG: Added Content-type header"
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "POST"){
				$header.Add('Content-Type','application/json')
				write-host "DEBUG: Added Content-type header"
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}else{
				throw "Incorrect method input for servicenow-header",1
			}
		if($script:debug){
			write-host "DEBUG: header:" $header
			write-host "DEBUG: headerobject.header:" $headerobject.header
			write-host "DEBUG: headerobject.methodtype:" $headerobject.methodtype
	}
		return $headerobject
}
function servicenow-header-oldway {
	Param(
			[Parameter(Mandatory=$true)][System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$methodtype
		)
			if($script:debug){
				write-host "DEBUG: Building Header:" -foreground "green"
				write-host "DEBUG:" $credential
				write-host "DEBUG:" $methodtype
			}
			$headerobject = New-Object System.Object
			$user = $credential.GetNetworkCredential().username
			$pass = $credential.GetNetworkCredential().password
			$secpass = ConvertTo-SecureString -AsPlainText -Force -String $pass
			$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
			$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$header.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
			$methodtype = $($methodtype.toUpper())
			#write-host $methodtype
			if($methodtype -eq "GET"){
				$header.Add('Accept','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "PATCH"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "PUT"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "POST"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}else{
				throw "Incorrect method input for servicenow-header",1
			}
		if($script:debug){
			write-host "DEBUG:" $headerobject.header
			write-host "DEBUG:" $headerobject.methodtype
		return $headerobject
	}
}
function servicenow-builduri-sysid {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$sysid
		)
		if($script:debug){
			write-host "DEBUG: servicenow-builduri-sysid" -foreground "green"
			write-host "DEBUG:" $sninstance
			write-host "DEBUG: " $tablename
			}
		$uri = "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "/" + $sysid
		if($script:debug){write-host "DEBUG:" $uri}
		return $uri
	}
function servicenow-builduri-searchlike {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$namelike
		)
		if($script:debug){
			write-host "DEBUG: servicenow-builduri-sysid"  -foreground "green"
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $tablename
			write-host "DEBUG:" $namelike
			}
		return "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "?sysparm_query=nameLIKE" + $namelike + "&sysparm_fields=sys_id%2Cname&sysparm_limit=1"
		if($script:debug){write-host "DEBUG: servicenow-builduri-sysid -" $uri}
	}
function servicenow-uri{
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$namespace,		#global|now|sn_codesearch/code_search/search|sn_devstudio/v1/vcs/apps
			[Parameter(Mandatory=$true)][string]$apiname,		#stats|attachment|guided_setup/change/log/update|identifyreconcile|import|pa|table
			[Parameter(Mandatory=$false)][string]$apitable1,
			[Parameter(Mandatory=$false)][string]$apitable2,
			[Parameter(Mandatory=$false)][string]$apitable3,
			[Parameter(Mandatory=$false)][string]$sysparam,
			[Parameter(Mandatory=$true)]$totalpages,
			[Parameter(Mandatory=$true)]$pagesize
		)
		if($script:debug){
			write-host "DEBUG: servicenow-uri" -foreground "green"
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $namespace
			write-host "DEBUG:" $apiname
			write-host "DEBUG:" $apitable1
			write-host "DEBUG:" $apitable2
			write-host "DEBUG:" $apitable3
			write-host "DEBUG:" $sysparam
			write-host "DEBUG:" $totalpages
			write-host "DEBUG:" $pagesize
			}
			
			
			
			$pageobjects = New-Object System.Object
		
		$list = New-Object System.Collections.Generic.List[System.Object]
		$page = 0
		For ($i=0; $i -le $totalpages; $i++) {
		
		$uri = "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "?sysparm_limit=" + $pagesize + "&sysparm_offset=" + $page
		#write-host $list
		$list.add($uri)
			$page = $page + $pagesize
		}		if($script:debug){
					write-host "DEBUG:" $list[0]
					write-host "DEBUG:" $list[1]
					}
		return $list
			
			
			
			
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $namespace
			write-host "DEBUG:" $apiname
			write-host "DEBUG:" $apitable1
			write-host "DEBUG:" $apitable2
			write-host "DEBUG:" $apitable3
			write-host "DEBUG:" $sysparam
			
			
			
			
			
			
	#	,
	#		[Parameter(Mandatory=$false)][string]$body
		
	#	if($apiversion.isPresent){$apiversion = $apiversion + "/"}
	if($apitable1.isPresent()){
	
	}
		$uri = "https://" + $sninstance + ".service-now.com/api" + $namespace + $apiname + $tablename + $property
		if($apiversion.isPresent){
			write-host "DEBUG:" $uri
			}
		return $uri
	}
function servicenow-instance {
	Param(
			[Parameter(Mandatory=$true)][string]$baseheader,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$namespace,		#global|now|sn_codesearch/code_search/search|sn_devstudio/v1/vcs/apps
			[Parameter(Mandatory=$true)][string]$apiname,		#stats|attachment|guided_setup/change/log/update|identifyreconcile|import|pa|table
			[Parameter(Mandatory=$true)][string]$apiversion,	#""|"v1/"|"v2/"
			[Parameter(Mandatory=$true)][string]$method,		#get|post|put|delete|patch but uppercase
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$false)][string]$property,
			[Parameter(Mandatory=$false)][string]$operator,
			[Parameter(Mandatory=$false)][string]$value,
			[Parameter(Mandatory=$false)][string]$body
		)
			$objServiceNow = New-Object System.Object
			$objServiceNow | Add-Member -type NoteProperty -name baseheader -Value $baseheader
			$objServiceNow | Add-Member -type NoteProperty -name sninstance -Value $sninstance
			$objServiceNow | Add-Member -type NoteProperty -name namespace -Value $namespace
			$objServiceNow | Add-Member -type NoteProperty -name apiname -Value $apiname
			$objServiceNow | Add-Member -type NoteProperty -name apiversion -Value $apiversion
			$objServiceNow | Add-Member -type NoteProperty -name method -Value $method
			$objServiceNow | Add-Member -type NoteProperty -name tablename -Value $tablename
			$objServiceNow | Add-Member -type NoteProperty -name property -Value $property
			$objServiceNow | Add-Member -type NoteProperty -name operator -Value $operator
			$objServiceNow | Add-Member -type NoteProperty -name value -Value $value
			$objServiceNow | Add-Member -type NoteProperty -name body -Value $body
			$objServiceNow | Add-Member -type NoteProperty -name header -Value $header
		return $objServiceNow
	}
<#
	
function servicenow-patch{
	Param(
		[System.Object]$objServiceNow,
		[string]$jsonbody
		}

	
	}
	
	#>
function servicenow-getsysid {
	Param(
			[Parameter(Mandatory=$true)][System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$namelike,
			[Parameter(Mandatory=$true)][string]$tablename		
		)
		if($script:debug){
			write-host "DEBUG: servicenow-getsysid" -foreground "green"
			write-host "DEBUG:" $credential
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $namelike
			write-host "DEBUG:" $tablename
			}
			$headerobject = servicenow-header -credential $credential -methodtype "get"
			$uri = servicenow-builduri-searchlike -sninstance $sninstance -tablename $tablename -namelike $namelike
			$content = servicenow-request -uri $uri -headerobject $headerobject
			if($content -ne $null){
				$nojson = convertfrom-json -inputobject $content
				if($content -like "*sys_id*"){ #should improve this condition check
					$sysid = $($content | convertfrom-json | select -expand result | Select sys_id).sys_id
					if($script:debug){write-host "DEBUG:" $sysid}
					return $sysid
				}
			}
			
		return $null
	}
function build-cred {
	Param(
			[Parameter(Mandatory=$true)][string]$user,
			[Parameter(Mandatory=$true)][string]$password
		)
		if($script:debug){
			write-host "DEBUG: build-cred" -foreground "green"
			write-host "DEBUG:" $user
			write-host "DEBUG:" $password
			}
		$secpass = ConvertTo-SecureString $password -AsPlainText -Force
	#	$mycred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user,$secpass  
		$cred = New-Object System.Management.Automation.PSCredential ($user, $secpass)
		if($script:debug){write-host "DEBUG:" $cred}
		return $cred
}
function servicenow-patch-bysysid { #need to remove tablename requirement
	Param(
			[System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$sysid,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)]$jsonbody
		)
			$headerobject = servicenow-header -credential $credential -methodtype "patch"
			$uri = servicenow-builduri-sysid -sninstance $sninstance -tablename $tablename -sysid $sysid
			$result = (servicenow-request -uri $uri -headerobject $headerobject -jsonbody $jsonbody)
		return $result.statuscode
	}
function bodycontent-dynamic {
	Param(
			[Parameter(Mandatory=$true)][string]$property,
			[Parameter(Mandatory=$true)][string]$value
		)
		$content = @{
			$property = $value
		}
		$json = (ConvertTo-Json -InputObject $content -compress)
	return $json
	}
function servicenow-request {
	Param(
			[Parameter(Mandatory=$true)][string]$uri,
			[Parameter(Mandatory=$false)]$headerobject,
			[Parameter(Mandatory=$false)]$header,
			[Parameter(Mandatory=$false)]$method,
			[Parameter(Mandatory=$false)]$jsonbody
		)
			$content = $null
			#$global:testobj = $headerobject
			if($script:debug){
				write-host "DEBUG: servicenow-request:" -foreground "green"
				write-host "DEBUG: uri:" $uri
				write-host "DEBUG: Headerobject.header:" $headerobject.header
				write-host "DEBUG: Headerobject.Method:" $headerobject.methodtype
				write-host "DEBUG: header:" $header
				write-host "DEBUG: Method:" $method
				write-host "DEBUG: JSON Body:" $jsonbody
			}
			try{
				if($headerobject -ne $null){
						write-host "DEBUG: Headerobject is present"
					if($jsonbody.IsPresent){
						write-host "DEBUG: json body is present"
						$content = Invoke-WebRequest -Uri $uri -Headers $headerobject.header -Method $headerobject.methodtype -Body $jsonbody
					}else{
						write-host "DEBUG: json body is NOT present"
						$content = Invoke-WebRequest -Uri $uri -Headers $headerobject.header -Method $headerobject.methodtype
				#		$content = Invoke-WebRequest -Uri $uri -Headers $header -Method $headerobject.methodtype
					}
				}else{`
						write-host "DEBUG: Headerobject is NOT present"
					if($jsonbody.IsPresent){
						write-host "DEBUG: json body is present"
						$content = Invoke-WebRequest -Uri $uri -Headers $header -Method $method -Body $jsonbody
					}else{
						write-host "DEBUG: json body is NOT present"
						write-host "DEBUG:" $uri.GetType()
						write-host "DEBUG:" $header.GetType()
						write-host "DEBUG:" $method.GetType()
						$content = Invoke-WebRequest -Uri $uri -Headers $header -Method $method
					}
				}
			}
			catch{
			if($script:debug){write-host "DEBUG: Content:" $content}
			}
			if($script:debug){write-host "DEBUG: Content:" $content}
		return $content
	}
function servicenow-builduri-gettable-pagination {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)]$totalpages,
			[Parameter(Mandatory=$true)]$pagesize
		)
		if($script:debug){
			write-host "DEBUG: servicenow-builduri-gettable-pagination:" -foreground "green"
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $tablename
			write-host "DEBUG:" $totalpages
			write-host "DEBUG:" $pagesize
		}
		$pageobjects = New-Object System.Object
		
		$list = New-Object System.Collections.Generic.List[System.Object]
		$page = 0
		For ($i=0; $i -le $totalpages; $i++) {
		
		$uri = "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "?sysparm_limit=" + $pagesize + "&sysparm_offset=" + $page
		#write-host $list
		$list.add($uri)
			$page = $page + $pagesize
		}		if($script:debug){
					write-host "DEBUG:" $list[0]
					write-host "DEBUG:" $list[1]
					}
		return $list
    }	
function servicenow-builduri-test {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$false)]$totalpages,
			[Parameter(Mandatory=$false)]$pagesize
		)
		if($script:debug){
			write-host "DEBUG: servicenow-builduri-test:" -foreground "green"
			write-host "DEBUG:" $sninstance
			write-host "DEBUG:" $tablename
			if($totalpages.isPresent){
				write-host "DEBUG:" $totalpages
				write-host "DEBUG:" $pagesize
				}
		}
		$pageobjects = New-Object System.Object
		$uri = $null
		$list = New-Object System.Collections.Generic.List[System.Object]
		if($totalpages.isPresent){
			$page = 0
			For ($i=0; $i -le $totalpages; $i++) {
				$uri = "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename
		#		+ "?sysparm_limit=" + $pagesize + "&sysparm_offset=" + $page
				#write-host $list
				$list.add($uri)
				#	$page = $page + $pagesize
			}
		}else{
			$uri = "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename
			$list += $uri
		}
		if($script:debug){
				write-host "DEBUG:" $uri
				write-host "DEBUG:" $list.length
				}
		return $list
    }		
function test-servicenow-request001 {
		#	Test executing each method and each searchtype
		clear
		$script:debug = $true
		$testusername = "admin"
		$testpassword = "uyzQEbB2D3J9"
		$cred = build-cred -user $testusername -password $testpassword
		#write-host $cred
		$testsninstance = "dev38113"
		$testtable = "incident"
		$testnamespace = "api/now/"
		$testheaderobject = servicenow-header -credential $cred -methodtype "get"
		$testlist = New-Object System.Collections.Generic.List[System.Object]
		#$testarruri = servicenow-builduri-gettable-pagination $testsninstance -tablename "incident" -totalpages 5 -pagesize 5
		$testarruri = servicenow-builduri-test -sninstance $testsninstance -tablename "incident" 
		#-totalpages 5 -pagesize 5
		#$headerobject = New-Object System.Object
		write-host "DEBUG: total number of test URI" $testarruri.length $testarruri
		write-host "DEBUG:" $testheaderobject.header
		write-host "DEBUG:" $testheaderobject.methodtype
		$method = "GET"
		$resultarray = @()
		foreach ($testuri in $testarruri){
			write-host "DEBUG: Looping URIs==========================================" $testarruri.indexOf($testuri) -foreground "green"
			#write-host $testuri
			$result = servicenow-request -uri $testuri -headerobject $testheaderobject
			#$result = servicenow-request -uri $testuri -header $testheaderobject.header -method $testheaderobject.methodtype
			#$headerobject | Add-Member -type NoteProperty -name asdf1234 -Value $result
			$resultarray += $result
			}
		
			return $resultarray
		
		}
function servicenow-restapi{
	Param(
			[Parameter(Mandatory=$true)][string]$baseheader,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$namespace,		#global|now|sn_codesearch/code_search/search|sn_devstudio/v1/vcs/apps
			[Parameter(Mandatory=$true)][string]$apiname,		#stats|attachment|guided_setup/change/log/update|identifyreconcile|import|pa|table
			[Parameter(Mandatory=$true)][string]$apiversion,	#""|"v1/"|"v2/"
			[Parameter(Mandatory=$true)][string]$method,		#get|post|put|delete|patch but uppercase
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$false)][string]$property,
			[Parameter(Mandatory=$false)][string]$operator,
			[Parameter(Mandatory=$false)][string]$value,
			[Parameter(Mandatory=$false)][string]$body
		)
			$objServiceNow = New-Object System.Object
			$objServiceNow | Add-Member -type NoteProperty -name baseheader -Value $baseheader
			$objServiceNow | Add-Member -type NoteProperty -name sninstance -Value $sninstance
			$objServiceNow | Add-Member -type NoteProperty -name namespace -Value $namespace
			$objServiceNow | Add-Member -type NoteProperty -name apiname -Value $apiname
			$objServiceNow | Add-Member -type NoteProperty -name apiversion -Value $apiversion
			$objServiceNow | Add-Member -type NoteProperty -name method -Value $method
			$objServiceNow | Add-Member -type NoteProperty -name tablename -Value $tablename
			$objServiceNow | Add-Member -type NoteProperty -name property -Value $property
			$objServiceNow | Add-Member -type NoteProperty -name operator -Value $operator
			$objServiceNow | Add-Member -type NoteProperty -name value -Value $value
			$objServiceNow | Add-Member -type NoteProperty -name body -Value $body
			$objServiceNow | Add-Member -type NoteProperty -name header -Value $header
		return $objServiceNow
	}
function checkit {
	Param(
		$objects
		)
		write-host "DEBUG: CHECKIT" $object
		foreach ($item in $objects){
			#write-host "DEBUG:" $objects.IndexOf($item)
			#write-host "DEBUG:" $item.countof
			write-host "DEBUG:" $item
		}
}
<#

servicenow-request {
	Param(
			[Parameter(Mandatory=$true)][string]$uri,
			[Parameter(Mandatory=$true)]$headerobject,
			[Parameter(Mandatory=$false)]$jsonbody
			
			
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$totalpages,
			[Parameter(Mandatory=$true)][string]$pagesize

			[Parameter(Mandatory=$true)][System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$methodtype
		)
		
		
		
function servicenow-builduri-gettable-pagination {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$totalpages,
			[Parameter(Mandatory=$true)][string]$pagesize
#>

