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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

public class IWAConfigUtil {
	private static Map<String, IWATenantConfig> tenantConfigMap = new HashMap<>();

	public static List<String> getTenants() {
		return new ArrayList<String>(tenantConfigMap.keySet());
	}

	public static String getSpnName(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = tenantConfigMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getSpnName();
		} else {
			return null;
		}
	}

	public static char[] getSpnPassword(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = tenantConfigMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getSpnPassword();
		} else {
			return null;
		}
	}

	public static List<String> getUserStoreDomains(String tenantDomain) {
		IWATenantConfig iwaTenantConfig = tenantConfigMap.get(tenantDomain);
		if (iwaTenantConfig != null) {
			return iwaTenantConfig.getUserStoreDomains();
		} else {
			return new ArrayList<String>();
		}
	}

	/**
	 * Build iwa-tenants.properties file
	 * 
	 * @throws IOException
	 */
	public static void buildIwaTenantsConfig() throws IOException {
		String iwaTenantsConfigPath = System.getProperty(IWAConstants.IWA_TENANTS_CONFIG_FILE);
		String carbonHome = System.getProperty(CarbonBaseConstants.CARBON_HOME);

		// Use default iwa-tenants.properties file path if not set by the system property already
		if (IdentityUtil.isBlank(iwaTenantsConfigPath)) {
			iwaTenantsConfigPath = Paths.get(carbonHome, "repository", "conf", "identity",
					IWAConstants.IWA_TENANTS_CONF_FILE_NAME).toString();
		}

		File iwaTenantsConfigFile = new File(iwaTenantsConfigPath);
		InputStream inStream = null;
		Properties properties = new Properties();

		if (iwaTenantsConfigFile.exists()) {
			try {
				inStream = new FileInputStream(iwaTenantsConfigFile);
				properties.load(inStream);
			} finally {
				if (inStream != null) {
					inStream.close();
				}
			}
		}
		loadIwaTenants(properties, IWAConstants.IWATenantsPropertyConfig.IWA_TENANTS);
	}

	/**
	 * Load IWA tenants from properties
	 * 
	 * @param properties
	 *            IWA Tenants config properties
	 * @param iwaTenantsType
	 *            Property type for IWA Tenants
	 */
	private static void loadIwaTenants(Properties properties, String iwaTenantsType) {
		Set<Integer> tenantsSet = new HashSet<>();
		Iterator<String> keyValues = properties.stringPropertyNames().iterator();
		while (keyValues.hasNext()) {
			String currentProp = keyValues.next();
			if (currentProp.startsWith(iwaTenantsType)) {
				String tenantNumber = currentProp.replaceFirst(iwaTenantsType + ".", "");
				if (StringUtils.isNumeric(tenantNumber)) {
					tenantsSet.add(Integer.parseInt(tenantNumber));
				}
			}
		}

		// Reading parameters of different tenants
		Iterator<Integer> tenantsIterator = tenantsSet.iterator();
		while (tenantsIterator.hasNext()) {
			Integer tenantIndex = tenantsIterator.next();
			String tenantDomain = properties.getProperty(iwaTenantsType + "." + tenantIndex);
			if (tenantDomain == null) {
				continue;
			}
			Map<String, String> tenantParameters = getParameters(properties, iwaTenantsType, tenantIndex);
			String spnName = tenantParameters.get(IWAConstants.IWATenantsPropertyConfig.SERVICE_PRINCIPAL_NAME);
			char[] spnPassword = tenantParameters.get(IWAConstants.IWATenantsPropertyConfig.SERVICE_PRINCIPAL_PASSWORD)
					.toCharArray();
			List<String> userStoreDomains = new ArrayList<String>(Arrays.asList(tenantParameters.get(
					IWAConstants.IWATenantsPropertyConfig.USERSTORE_DOMAINS).split(",")));
			IWATenantConfig iwaTenantConfig = new IWATenantConfig(tenantDomain, spnName, spnPassword, userStoreDomains);
			tenantConfigMap.put(tenantDomain, iwaTenantConfig);
		}
	}

	/**
	 * Get parameters of tenant properties
	 * 
	 * @param properties
	 * @param tenantType
	 * @param tenantIndex
	 * @return
	 */
	private static Map<String, String> getParameters(Properties properties, String tenantType, int tenantIndex) {
		Set<String> keys = properties.stringPropertyNames();
		Map<String, String> keyValues = new HashMap<String, String>();

		for (String key : keys) {
			if (key.contains(tenantType + "." + String.valueOf(tenantIndex))) {
				Pattern propertyPattern = Pattern.compile(IWAConstants.IWATenantsPropertyConfig.IWA_PATTERN_STRING);
				Matcher matcher = propertyPattern.matcher(key);
				if (matcher.find()) {
					int searchIndex = matcher.end();
					if (key.length() > searchIndex) {
						String propKey = key.substring(searchIndex);
						String propValue = properties.getProperty(key);
						keyValues.put(propKey, propValue);
					}
				}

			}
		}
		return keyValues;
	}
}

class IWATenantConfig {
	private String tenantName;
	private String spnName;
	private char[] spnPassword;
	private List<String> userStoreDomains;

	public IWATenantConfig() {
	}

	IWATenantConfig(String tenantName, String spnName, char[] spnPassword, List<String> userStoreDomains) {
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