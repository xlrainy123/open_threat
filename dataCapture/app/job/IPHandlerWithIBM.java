package job;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import okhttp3.OkHttpClient;
import utils.IBMUtil;
import utils.model.IBMIntell;
import utils.model.IntellegentInterface;

public class IPHandlerWithIBM implements Runnable{
	public List<IntellegentInterface> intelligents = new ArrayList<>();
	public Set<Object> malware = null;
	public String ip;
	public OkHttpClient client = null;
	public boolean complete = false;
	private CountDownLatch count;
	
	public IPHandlerWithIBM() {
		
	}
	public IPHandlerWithIBM(CountDownLatch count, OkHttpClient client, 
			Set<Object> malware, List<IntellegentInterface> intelligents) {
		this.client = client;
		this.count = count;
		this.intelligents = intelligents;
		this.malware = malware;
	}
	public void parserIntellegent() {
		JSONObject all = new IBMUtil().getIpReport(ip);
		JSONArray array = null;
	    try {
	    	array = all.getJSONArray("history");
	    }catch (Exception e) {
			array = new JSONArray();
		}
	    if (!array.isEmpty()) {
	    	for (Object json : array) {
	    		String cat = "", reasonDescription = "", created = "";
	    		try {
	    			cat = ((JSONObject)json).getString("cats");
	    		}catch(Exception e) {
	    			cat = "";
	    		}
	    		try {
	    			reasonDescription = ((JSONObject)json).getString("reasonDescription");
	    		}catch(Exception e) {
	    			reasonDescription = "";
	    		}
	    		try {
	    			created = ((JSONObject)json).getString("created");
	    		}catch(Exception e) {
	    			created = "";
	    		}
	    		IBMIntell intelligent = new IBMIntell();
				intelligent.description = reasonDescription;
				intelligent.time = created;
				intelligent.type = retriveType(cat);
				intelligent.source = "open IBM";
				intelligents.add(intelligent);
			}
	    	System.out.println("----------------IBM  intelligents:"+intelligents.size());
	    }
	}
	
	public String retriveType(String cat) {
		if ("".equals(cat)) {
			return cat;
		}
		String[] strings = cat.trim().split("\"");
		if (strings.length < 2) {
			return cat;
		}
		return !"".equals(strings[1]) ? strings[1] : cat; 
	}
	public void parserMalware() {
		JSONObject malwareAll = new IBMUtil().getMalwareFromIp(ip);
		JSONArray malwareArray = null;
		try {
			malwareArray = malwareAll.getJSONArray("malware");
		}catch (Exception e) {
			malwareArray = new JSONArray();
		}
		for (Object object : malwareArray) {
			String md5 = "";
			try {
				md5 = ((JSONObject)object).getString("md5");
			}catch (Exception e) {
				md5 = "";
			}
			if (!"".equals(md5)) {
				malware.add("'"+md5+"'");
			}
		}
		System.out.println("-----------------IBM malware:"+malware.size());
	}
	
	public void run() {
		parserIntellegent();
		parserMalware();
		complete = true;
		count.countDown();
	}
}
