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
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.TemporaryExtractionLocation;
import com.denimgroup.threadfix.framework.util.EndpointUtil;
import java.io.File;

import javax.swing.JOptionPane;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class LocalEndpointsButton extends EndpointsButton {
    private String errorMessage = "An error occurred processing input. Please check input";

    public LocalEndpointsButton(final Component view, final IBurpExtenderCallbacks callbacks) { super(view, callbacks, 0); }

    @Override
    protected String getButtonText() {
        return "Import Endpoints from Source";
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
    protected  String getErrorMessage() {return errorMessage;}

    @Override
    protected EndpointDecorator[] getEndpoints(final Component view, boolean compare)
    {
        String sourceFolder;
        if (compare)
        {
            sourceFolder = BurpPropertiesManager.getBurpPropertiesManager().getOldSourceFolder();
        }
        else
        {
            sourceFolder = BurpPropertiesManager.getBurpPropertiesManager().getSourceFolder();
        }
        File file= new File(sourceFolder);
        TemporaryExtractionLocation zipExtractor = null;
        if (TemporaryExtractionLocation.isArchive(sourceFolder)) {
            zipExtractor = new TemporaryExtractionLocation(sourceFolder);
            zipExtractor.extract();

            file = zipExtractor.getOutputPath();
        }

        List<FrameworkType> frameworks = FrameworkCalculator.getTypes(file);
        ArrayList<List<Endpoint>> endpointsListList =new ArrayList<>(frameworks.size());
        EndpointDecorator[] endpoints = null;
        int decSize = 0;
        for (FrameworkType framework :  frameworks)
        {
            EndpointDatabase endpointDatabase = EndpointDatabaseFactory.getDatabase(file, framework);
            if(endpointDatabase != null)
            {
                List<Endpoint> endpointsList = EndpointUtil.flattenWithVariants(endpointDatabase.generateEndpoints());
                endpointsListList.add(endpointsList);
                decSize += endpointsList.size();
            }
        }
        endpoints = new EndpointDecorator[decSize];
        int pos = 0;
        for(List<Endpoint> endpointList: endpointsListList)
        {
            for(Endpoint endpoint : endpointList)
            {
                endpoints[pos++] = new EndpointDecorator(Endpoint.Info.fromEndpoint(endpoint, false));
            }
        }

        if (zipExtractor != null) {
            zipExtractor.release();
        }
        return endpoints;
    }

}
