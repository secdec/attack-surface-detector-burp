////////////////////////////////////////////////////////////////////////////////////////
//
//     Copyright (C) 2017 Applied Visions - http://securedecisions.com
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
//     This material is based on research sponsored by the Department of Homeland
//     Security (DHS) Science and Technology Directorate, Cyber Security Division
//     (DHS S&T/CSD) via contract number HHSP233201600058C.
//
//     Contributor(s):
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////////////////////
package burp.extention;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class RequestMakerThread implements Runnable
{
    private IBurpExtenderCallbacks callbacks;
    private Component view;

    public RequestMakerThread(IBurpExtenderCallbacks callbacks, Component view)
    {
        this.callbacks = callbacks;
        this.view = view;
    }

    public void run()
    {
        try
        {
            HashMap<RequestDecorator, IHttpService> requests = BurpPropertiesManager.getBurpPropertiesManager().getRequests();
            Set<Map.Entry<RequestDecorator, IHttpService>> st = requests.entrySet();
            int i = 1;
            for (Map.Entry<RequestDecorator, IHttpService> me : st)
            {
                IHttpRequestResponse reqRep = callbacks.makeHttpRequest(me.getValue(),me.getKey().getRequest());
                if(me.getKey().getModified() == EndpointDecorator.Status.CHANGED)
                {
                    reqRep.setHighlight("magenta");
                    reqRep.setComment("Modified endpoint detected by Attack Surface Difference Generator");
                }
                else if(me.getKey().getModified() == EndpointDecorator.Status.NEW)
                {
                    reqRep.setHighlight("orange");
                    reqRep.setComment("New endpoint detected by Attack Surface Difference Generator");
                }
                else
                {
                    reqRep.setHighlight("cyan");
                    reqRep.setComment("Endpoint detected by Attack Surface Detector");
                }

                callbacks.addToSiteMap(reqRep);

            }
        }
        catch(Exception e)
        {
            JOptionPane.showMessageDialog(view, e.getMessage(),
                    "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }
}


