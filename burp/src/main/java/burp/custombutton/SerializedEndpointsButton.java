///////////////////////////////////////////////////////////////////////////////
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

package burp.custombutton;

import burp.EndpointDecorator;
import burp.IBurpExtenderCallbacks;
import burp.dialog.ConfigurationDialogs;
import burp.extention.BurpPropertiesManager;
import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointSerialization;

import com.denimgroup.threadfix.framework.engine.full.RouteParameterDeserializer;
import org.codehaus.jackson.Version;
import org.codehaus.jackson.map.module.SimpleModule;
import org.codehaus.jackson.annotate.JsonAutoDetect;
import org.codehaus.jackson.annotate.JsonMethod;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.type.TypeFactory;

import javax.swing.JOptionPane;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;


public class SerializedEndpointsButton extends EndpointsButton {

    private Component view;

    private String errorMessage;

    public SerializedEndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) { super(view, callbacks, 1); this.view = view; }

    @Override
    protected String getButtonText() {
        return "Import Endpoints from CLI JSON";
    }

    @Override
    protected String getNoEndpointsMessage() { return "Failed to retrieve endpoints from the source. Check your JSON file."; }

    @Override
    protected String getCompletedMessage() { return "The endpoints were successfully generated from JSON."; }

    @Override
    protected  String getErrorMessage() {return errorMessage;}

    @Override
    protected ConfigurationDialogs.DialogMode getDialogMode() {
        return ConfigurationDialogs.DialogMode.SOURCE;
    }

    @Override
    protected EndpointDecorator[] getEndpoints(final Component view, boolean compare) {
        EndpointDecorator[] endpoints = null;
        String fileName;
        if(compare)
        {
            fileName = BurpPropertiesManager.getBurpPropertiesManager().getOldSerializationFile();
        }
        else
        {
            fileName = BurpPropertiesManager.getBurpPropertiesManager().getSerializationFile();
        }
        try
        {
            File file = new File(fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            String endpointsStr = new String(data, "UTF-8");
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setVisibility(JsonMethod.ALL, JsonAutoDetect.Visibility.NONE);
            objectMapper.setVisibility(JsonMethod.FIELD, JsonAutoDetect.Visibility.ANY);
            SimpleModule module = new SimpleModule("RouteParameterDeserializer", Version.unknownVersion());
            module.addDeserializer(RouteParameter.class, new RouteParameterDeserializer());
            objectMapper.registerModule(module);
            Endpoint.Info[] endpointList = objectMapper.readValue(endpointsStr, TypeFactory.defaultInstance().constructArrayType(Endpoint.Info.class));
            endpoints = new EndpointDecorator[endpointList.length];
            for(int i = 0; i < endpointList.length; i++ )
            {
                endpoints[i] = new EndpointDecorator(endpointList[i]);
            }

        }
        catch(FileNotFoundException ex)
        {
            System.out.println("Unable to open file '" + fileName + "'");
            errorMessage = "Unable to open file '" + fileName + "'";
        }
        catch(IOException ex)
        {
            System.out.println("Error reading file '" + fileName + "'" + ex.toString());
            errorMessage = "The JSON file is either corrupt or is using an old format." + "\n" + "Please regenerate your JSON file using the latest version of the Attack Surface Detector CLI Tool.";
        }
        catch (Exception e)
        {
            System.out.println("An error occurred processing input. Please check input" + e.toString());
            errorMessage = "An error occurred processing input. Please check input";
        }
        return endpoints;
    }

}

