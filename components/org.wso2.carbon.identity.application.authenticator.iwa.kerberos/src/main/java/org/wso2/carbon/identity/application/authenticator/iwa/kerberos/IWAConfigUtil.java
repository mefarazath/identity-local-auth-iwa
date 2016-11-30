/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.iwa.kerberos;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IWAConfigUtil {

	private Map<String, IWATenantConfig> configMap = new HashMap<>();

	public List<String> getTenants() {
		return new ArrayList<String>(configMap.keySet());
	}

	public String getSpnName(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = configMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getSpnName();
		} else {
			return null;
		}
	}

	public char[] getSpnPassword(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = configMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getSpnPassword();
		} else {
			return null;
		}
	}

	public List<String> getUserStoreDomains(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = configMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getUserStoreDomains();
		} else {
			return new ArrayList<String>();
		}
	}

}

class IWATenantConfig {

	private String tenantName;
	private String spnName;
	private char[] spnPassword;
	private List<String> userStoreDomains;

	public IWATenantConfig() {
	}

	IWATenantConfig(String tenantName, String spnName, char[] spnPassword,
			List<String> userStoreDomains) {
		this.tenantName = tenantName;
		this.spnName = spnName;
		this.spnPassword = spnPassword;
		this.userStoreDomains = userStoreDomains;
	}

	public String getTenantName() {
		return tenantName;
	}

	public String getSpnName() {
		return spnName;
	}

	public char[] getSpnPassword() {
		return spnPassword;
	}

	public List<String> getUserStoreDomains() {
		return userStoreDomains;
	}
}