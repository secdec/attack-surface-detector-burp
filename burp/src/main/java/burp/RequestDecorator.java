package burp;

public class RequestDecorator {
    private byte[] request;
    private EndpointDecorator.Status modified;

    public RequestDecorator(byte[] request, EndpointDecorator.Status modified)
    {
        this.request = request.clone();
        this.modified = modified;
    }

    public byte[] getRequest() { return request.clone(); }

    public void setRequest(byte[] request)
    {
        this.request = request.clone();
    }

    public EndpointDecorator.Status getModified()
    {
        return modified;
    }

    public void setModified(EndpointDecorator.Status modified)
    {
        this.modified = modified;
    }
}
