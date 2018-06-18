package utils.model;

public class CymonIntell extends IntellegentInterface{
	public String source = "open cymon";
	public String description;
//	public String time;
	public String tag;
	
	public String toString() {
		return "{"+"'source'"+":"+"'"+source+"'"+",'description'"+":"+"'"+description+"'"+",'type'"+":"+"'"+tag+"'"+",'time'"+":"+"'"+time+"'"+"}";
	}
}
