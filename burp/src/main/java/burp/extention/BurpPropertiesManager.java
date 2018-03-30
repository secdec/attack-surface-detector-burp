////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s):
//              Denim Group, Ltd.
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////

package burp.extention;


import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import com.denimgroup.threadfix.properties.PropertiesManager;
import org.hibernate.resource.transaction.backend.jta.internal.JtaIsolationDelegate;

import javax.swing.*;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Properties;

public class BurpPropertiesManager extends PropertiesManager {
    private static BurpPropertiesManager instance = null;

    public static final String
            TARGET_URL_KEY = "threadfix.target-url",
            SOURCE_FOLDER_KEY = "threadfix.source-folder",
            CONFIG_FILE_KEY = "threadfix.config-file",
            TARGET_PORT_KEY = "threadfix.port",
            TARGET_PATH_KEY = "threadfix.path",
            TARGET_HOST_KEY = "threadfix.host",
            USE_HTTPS_KEY = "threadfix.http";

    private static final Map<String, String> defaultPropertyValues = new HashMap<String, String>();
    static {

        defaultPropertyValues.put(USE_HTTPS_KEY, "false");
        defaultPropertyValues.put(SOURCE_FOLDER_KEY, "");
    }

    private static HashMap<byte[], IHttpService> requests = new HashMap<byte[], IHttpService>();
    private static IBurpExtenderCallbacks callbacks;
    private static Properties properties = new Properties();
    private static boolean hasChanges = false;
    private static JTable endpointsTable;
    private  static JLabel countLabel;
    private static JCheckBox httpsField;

    public static boolean
        AUTO_SCAN_KEY = false,
        AUTO_SPIDER_KEY = false;

    private BurpPropertiesManager(IBurpExtenderCallbacks callbacks) {
        super();
        this.callbacks = callbacks;
    }

    public static BurpPropertiesManager generateBurpPropertiesManager(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            instance = new BurpPropertiesManager(callbacks);
            return instance;
        }
        throw new RuntimeException("A BurpPropertiesManager already exists.");
    }

    public static BurpPropertiesManager getBurpPropertiesManager() {
        return instance;
    }

    public String getPropertyValue(String key) {
        String value = properties.getProperty(key);
        if (value == null) {
            value = callbacks.loadExtensionSetting(key);
        }
        if ((value == null) || (value.trim().equals(""))) {
            return defaultPropertyValues.get(key);
        }
        return value;
    }


    public void setPropertyValue(String key, String value) {
        properties.setProperty(key, value);
        hasChanges = true;
    }


    public void saveProperties() {
        if (hasChanges) {
            for (String key : properties.stringPropertyNames()) {
                String newValue = properties.getProperty(key);
                String oldValue = callbacks.loadExtensionSetting(key);
                if (!newValue.equals(oldValue)) {
                    callbacks.saveExtensionSetting(key, newValue);
                    properties.remove(key);
                }
            }
            hasChanges = false;
        }
    }

    @Override
    public void setMemoryKey(String newKey) {
        setKey(newKey);
    }

    @Override
    public void setMemoryUrl(String newUrl) {
        setUrl(newUrl);
    }


    public String getTargetUrl() {
        //return getPropertyValue(TARGET_URL_KEY);
        if (getUseHttps())
           return "https://" + getPropertyValue(TARGET_HOST_KEY)  + ":" + getPropertyValue(TARGET_PORT_KEY) + "/" + getPropertyValue(TARGET_PATH_KEY);
       else
            return "http://" + getPropertyValue(TARGET_HOST_KEY)  + ":" + getPropertyValue(TARGET_PORT_KEY) + "/" + getPropertyValue(TARGET_PATH_KEY);
    }

    public void setTargetUrl(String newTargetUrl)
    {
      setPropertyValue(TARGET_URL_KEY, newTargetUrl);
    }

    public String getSourceFolder() {
        return getPropertyValue(SOURCE_FOLDER_KEY);
    }

    public void setSourceFolder(String newSourceFolder) {
        setPropertyValue(SOURCE_FOLDER_KEY, newSourceFolder);
    }

    public String getConfigFile() {
        return getPropertyValue(CONFIG_FILE_KEY);
    }

    public void setConfigFile(String newConfigFile) {
        setPropertyValue(CONFIG_FILE_KEY, newConfigFile);
    }

    public boolean getAutoSpider() { return AUTO_SPIDER_KEY; }

    public boolean getAutoScan() { return AUTO_SCAN_KEY; }

    public void setAutoSpider(boolean newAutoSpider) {  AUTO_SPIDER_KEY = newAutoSpider; }

    public void setAutoScan(boolean newAutoScan) {  AUTO_SCAN_KEY = newAutoScan; }

    public boolean isProVersion() {return callbacks.getBurpVersion()[0].toLowerCase().contains("professional");}

    public HashMap<byte[], IHttpService> getRequests() {return requests;}

    public void setRequests(HashMap<byte [], IHttpService> requests) {this.requests = requests;}

    public void setEndpointsTable(JTable table){endpointsTable = table;}

    public static JTable getEndpointsTable() {return endpointsTable;}

    public void setCountLabel(JLabel label){countLabel = label;}

    public static JLabel getCountLabel() {return countLabel;}

    public String getTargetHost() {return getPropertyValue(TARGET_HOST_KEY);}

    public void setTargetHost(String newTargetHost) {setPropertyValue(TARGET_HOST_KEY, newTargetHost);}

    public String getTargetPort() {return getPropertyValue(TARGET_PORT_KEY);}

    public void setTargetPort(String newTargetPort) {setPropertyValue(TARGET_PORT_KEY, newTargetPort);}

    public String getTargetPath() {return getPropertyValue(TARGET_PATH_KEY);}

    public void setTargetPath(String newTargetPath) {setPropertyValue(TARGET_PATH_KEY, newTargetPath);}

    public IBurpExtenderCallbacks getCallbacks(){return callbacks;}

    public JCheckBox getUseHttpsField() {return httpsField;}

    public void setUseHttpsField(JCheckBox newField){httpsField = newField;}

    public boolean getUseHttps()
    {
        if(getPropertyValue(USE_HTTPS_KEY).equalsIgnoreCase("true"))
            return true;
        else
            return false;
    }

    public void setUseHttps(boolean newUseHttp)
    {
        if(newUseHttp)
        {
            setPropertyValue(USE_HTTPS_KEY, "true");
            httpsField.setSelected(true);
        }
        else
        {
            setPropertyValue(USE_HTTPS_KEY, "false");
            httpsField.setSelected(false);
        }
    }

}
