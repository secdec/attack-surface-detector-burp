package burp;

import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Map;

public class EndpointDecorator {
    private Endpoint.Info endpoint;
    private Endpoint.Info comparePoint;
    private Status status;

    public EndpointDecorator(Endpoint.Info endpoint)
    {
        this.endpoint = endpoint;
        status = Status.UNCHANGED;
    }

    public Endpoint.Info getEndpoint()
    {
        return endpoint;
    }

    public void setEndpoint(Endpoint.Info newPoint)
    {
        endpoint = newPoint;
    }

    public Endpoint.Info getComparePoint()
    {
        return comparePoint;
    }

    public void setComparePoint(Endpoint.Info comparePoint)
    {
        this.comparePoint = comparePoint;
    }

    public Status getStatus()
    {
        return status;
    }

    public void setStatus(Status status)
    {
        this.status = status;
    }

    public int checkSum() {
        HashCodeBuilder hb = new HashCodeBuilder();
                hb.append(endpoint.getHttpMethod());
                hb.append(endpoint.getUrlPath());

        for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
        {
            hb.append(parameter.getValue().toString());
            hb.append(parameter.getKey());
        }

        return  hb.toHashCode();
    }


   public enum Status
    {
        UNCHANGED, CHANGED, NEW
    }

}

