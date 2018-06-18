package controllers;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;

import io.ebean.Ebean;
import job.Client;
import models.IP;
import net.sf.json.JSONObject;
import play.mvc.Controller;
import play.mvc.Result;
import utils.IBMUtil;
import utils.dataHandler.IBMHandler;
import utils.factory.DataFactory;

public class IBMData extends Controller{
	public Result saveIpFromTxt() throws IOException , FileNotFoundException{
//		Map<String, String[]> params = request().queryString();
//		String path = params.get("path")[0];
//		if ("".equals(path)) {
//			return ok("invalid path");
//		}
		String path1 = "/home/x/Desktop/ip_all.txt";
		java.io.File file = new java.io.File(path1);
		BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
		String ip = "";
		List<IP> ips = new ArrayList<>();
		while((ip = reader.readLine()) != null) {
			System.out.println(ip);
			IP instance = new IP();
			instance.ip = ip;
			ips.add(instance);
		}
		Ebean.saveAll(ips);
		return ok("success");
	}
	public Result paramTest() {
		Map<String, String[]> params = request().queryString();
		String[] param = params.get("param");
		for (String string : param) {
			System.out.println("----- "+string);
		}
		return ok("success");
	}
	public Result getIp() {
		IP ip = new IP();
		ip.category = "";
		ip.created = "";
		ip.ip = "1";
		ip.score = 6.5;
		ip.save();
		return ok("success");
	}
	public Result ipReport() {
//		JSONObject all = DataFactory.getIBMInstance().getIpReport("223.5.5.5");
		JSONObject all = new IBMUtil().getIpReport("173.236.157.165");
		return ok(new Gson().toJson(all)).as("application/json");
//		return ok("success");
	}
	
	public Result getIp2Category(){
		Map<String, String[]> params = request().queryString();
		String[] category = params.get("category");
		if (category == null || category.length == 0) {
			IBMHandler.getIp("sip");
			IBMHandler.getIp("spam");
			IBMHandler.getIp("malware");
			IBMHandler.getIp("as");
			IBMHandler.getIp("Bots");
			IBMHandler.getIp("bcacs");
			return ok("success");
		}
		JSONObject all = IBMHandler.getIp(category[0]);
		return ok(new Gson().toJson(all)).as("application/json");
	}
	public Result getIpInfo() {
		List<Integer> ids = new ArrayList<>(); 
		Map<String, String[]> params = request().queryString();
		String start = params.get("start")[0];
		String end = params.get("end")[0];
		for (int i = Integer.parseInt(start); i <= Integer.parseInt(end); i++) {
			ids.add(i);
		}
		System.out.println("satrt:"+start+", end:"+end);
		List<IP> ips = IP.find.query().where().in("id", ids).findList();
		Client client = new Client(ips.size());
		client.execute(ips);
		return ok("success");
	}
	
	public Result getMalware(){
		IBMUtil ibm = (IBMUtil)DataFactory.getIBMInstance();
		JSONObject all = ibm.getMalwareFromIp("186.167.248.148");
		return ok(new Gson().toJson(all)).as("application/json");
	}
	
	public Result resoveIpDnsUrl(){
		IBMUtil ibm = (IBMUtil)DataFactory.getIBMInstance();
		JSONObject all = ibm.resolveIpDnsUrl("1.2.3.4");
		return ok(new Gson().toJson(all)).as("application/json");
	}
	
	public Result test() {
		long start = System.currentTimeMillis();
		System.out.println("time used :"+ (System.currentTimeMillis() - start));
		return ok("success");
	}
}
