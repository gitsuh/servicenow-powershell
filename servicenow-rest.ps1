#steven goodpaster
#6/29/2017

function servicenow-build-header {
	Param(
			[System.Management.Automation.CredentialAttribute()]$credential,
			[string]$methodtype
		)
			$headerobject = New-Object System.Object
			$user = $credential.GetNetworkCredential().username
			$pass = $credential.GetNetworkCredential().password
			$secpass = ConvertTo-SecureString -AsPlainText -Force -String $pass
			$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $pass)))
			$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$header.Add('Authorization',('Basic {0}' -f $base64AuthInfo))
			if($methodtype -eq "get"){
				$header.Add('Accept','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "patch"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "put"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}elseif($methodtype -eq "post"){
				$header.Add('Content-Type','application/json')
				$headerobject | Add-Member -type NoteProperty -name header -Value $header
				$headerobject | Add-Member -type NoteProperty -name methodtype -Value $methodtype
			}else{
				throw "Incorrect method input for servicenow-build-header",1
			}
		return $headerobject
	}
function servicenow-builduri-sysid {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$sysid
		)	
		return "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "/" + $sysid
	}
function servicenow-builduri-searchlike {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$namelike
		)
		return "https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "?sysparm_query=nameLIKE" + $namelike + "&sysparm_fields=sys_id%2Cname&sysparm_limit=1"
	}
function servicenow-builduri-gettable-pagination {
	Param(
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)][string]$totalpages,
			[Parameter(Mandatory=$true)][string]$pagesize
		)		
		$list = New-Object System.Collections.Generic.List[System.Object]
		$page = 0
		For ($i=0; $i -le $totalpages; $i++) {
		$list.add("https://" + $sninstance + ".service-now.com/api/now/table/" + $tablename + "?sysparm_limit=" + $pagesize + "&sysparm_offset=" + $page)
			$page = $page + $pagesize
		}
		return $list
    }
function servicenow-getsysid {
	Param(
			[System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$namelike,
			[Parameter(Mandatory=$true)][string]$tablename		
		)
			$headerobject = servicenow-build-header -credential $credential -methodtype "get"
			$uri = servicenow-builduri-searchlike -sninstance $sninstance -tablename $tablename -namelike $namelike
			$content = servicenow-request -uri $uri -headerobject $headerobject
			if($content -ne $null){
				$nojson = convertfrom-json -inputobject $content
				if($content -like "*sys_id*"){ #should improve this condition check
					$sysid = $($content | convertfrom-json | select -expand result | Select sys_id).sys_id
					return $sysid
				}
			}
		return $null
	}
function servicenow-patchbysysid { #need to remove tablename requirement
	Param(
			[System.Management.Automation.CredentialAttribute()]$credential,
			[Parameter(Mandatory=$true)][string]$sninstance,
			[Parameter(Mandatory=$true)][string]$sysid,
			[Parameter(Mandatory=$true)][string]$tablename,
			[Parameter(Mandatory=$true)]$jsonbody
		)
			$headerobject = servicenow-build-header -credential $credential -methodtype "patch"
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
			[Parameter(Mandatory=$true)]$headerobject,
			[Parameter(Mandatory=$false)]$jsonbody
		)
			try{
				if($jsonbody.IsPresent){
					$content = Invoke-WebRequest -Uri $uri -Headers $headerobject.header -Method $headerobject.methodtype -Body $jsonbody
				}else{
					$content = Invoke-WebRequest -Uri $uri -Headers $headerobject.header -Method $headerobject.methodtype
				}
			}
			catch{
			}
		return $content
	}
