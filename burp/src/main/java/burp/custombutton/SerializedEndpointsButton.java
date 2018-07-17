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
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.EndpointSerializer;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointSerialization;
import com.denimgroup.threadfix.framework.util.EndpointUtil;

import javax.swing.JOptionPane;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class SerializedEndpointsButton extends EndpointsButton {

    public SerializedEndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) { super(view, callbacks, 1); }

    @Override
    protected String getButtonText() {
        return "Import Endpoints from CLI JSON";
    }

    @Override
    protected String getNoEndpointsMessage() { return "Failed to retrieve endpoints from the source. Check your source folder location."; }

    @Override
    protected String getCompletedMessage() { return "The endpoints were successfully generated from source."; }

    @Override
    protected ConfigurationDialogs.DialogMode getDialogMode() {
        return ConfigurationDialogs.DialogMode.SOURCE;
    }

    @Override
    protected EndpointDecorator[] getEndpoints(final Component view) {
        EndpointDecorator[] endpoints = null;
        String fileName = BurpPropertiesManager.getBurpPropertiesManager().getSerializationFile();

        try
        {
            File file = new File(fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            String endpointsStr = new String(data, "UTF-8");
            Endpoint[] endpointList = EndpointSerialization.deserializeAll(endpointsStr);
            endpoints = new EndpointDecorator[endpointList.length];
            int i = 0;
            for(Endpoint endpoint : endpointList)
                endpoints[i++] = new EndpointDecorator(Endpoint.Info.fromEndpoint(endpoint));

        }
        catch(FileNotFoundException ex)
        {
            System.out.println("Unable to open file '" + fileName + "'");
        }
        catch(IOException ex)
        {
            System.out.println("Error reading file '" + fileName + "'");
        }
        return endpoints;
    }

    @Override
    protected EndpointDecorator[] getComparePoints(final Component view)
    {
        EndpointDecorator[] endpoints = null;
        String fileName = BurpPropertiesManager.getBurpPropertiesManager().getOldSerializationFile();

        try
        {
            File file = new File(fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            String endpointsStr = new String(data, "UTF-8");
            Endpoint[] endpointList = EndpointSerialization.deserializeAll(endpointsStr);
            endpoints = new EndpointDecorator[endpointList.length];
            int i = 0;
            for(Endpoint endpoint : endpointList)
                endpoints[i++] = new EndpointDecorator(Endpoint.Info.fromEndpoint(endpoint));

        }
        catch(FileNotFoundException ex)
        {
            System.out.println("Unable to open file '" + fileName + "'");
        }
        catch(IOException ex)
        {
            System.out.println("Error reading file '" + fileName + "'");
        }
        return endpoints;
    }
}

