package utils.Interface;

import net.sf.json.JSONObject;

public interface IP {
	
	public abstract void getIp();
	public JSONObject getIpAccordingCategory(String category);
	public abstract JSONObject getIpReputation(String ip);
	public abstract JSONObject getMalwareFromIp(String ip);
	public abstract JSONObject resolveIpDnsUrl(String content);
}
