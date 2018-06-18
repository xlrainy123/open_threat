package controllers;

import com.google.gson.Gson;

import net.sf.json.JSONObject;
import play.mvc.Controller;
import play.mvc.Result;
import utils.VirustotalUtil;
import utils.factory.DataFactory;

public class VirustotalData extends Controller{
	
	public Result getIpReport() {
		JSONObject all = null;
		VirustotalUtil virustotalUtil = (VirustotalUtil) DataFactory.getVirustatolInstance();
		all = virustotalUtil.getIpReport("145.14.144.78");
		return ok(new Gson().toJson(all)).as("application/json");
	}
}
