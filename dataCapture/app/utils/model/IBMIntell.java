package utils.model;

public class IBMIntell extends IntellegentInterface{
	public Integer id;
	public String source = "open IBM";
	public String type = "scan";
	public String description;
//	public String time;
	
	public String toString() {
		return "{"+"'source'"+":"+"'"+source+"'"+",'type'"+":"+"'"+type+"'"+",'description'"+":"+"'"+description+"'"+",'time'"+":"+"'"+time+"'"+"}";
	}
}
