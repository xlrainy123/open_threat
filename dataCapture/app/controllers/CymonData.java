package controllers;


import java.util.List;

import com.google.gson.Gson;

import models.IP;
import net.sf.json.JSONObject;
import play.mvc.Controller;
import play.mvc.Result;
import utils.CymonUtil;
import utils.CymonNoProxy;
import utils.factory.DataFactory;

public class CymonData extends Controller{
	
	public Result getIpReport() {
		CymonUtil cymonUtil = (CymonUtil)DataFactory.getCymonInstance();
//		JSONObject all = cymon.getIpReport("103.235.46.39");
		JSONObject urlAll = new CymonNoProxy().getIpReportWithUrl("103.235.46.39");
		return ok(new Gson().toJson(urlAll)).as("application/json");
	}
	
	public Result clickme() {
		List<IP> ips = IP.find.all();
		return ok(views.html.showip.render(ips));
	}
}
