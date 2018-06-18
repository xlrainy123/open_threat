package utils.Interface;

import net.sf.json.JSONObject;

public interface Data {
	
	public abstract JSONObject getIpReportWithDomain(String ip);
	public abstract JSONObject getIpReportWithUrl(String ip);
	public abstract JSONObject getIpReportWithEvent(String ip);
	public abstract JSONObject getIpReport(String ip);
	public abstract JSONObject getDnsReport(String ip);
	public abstract JSONObject getUrlReport(String ip);
	
	public default boolean isIp(String ip) {
		return true;
	}
}
