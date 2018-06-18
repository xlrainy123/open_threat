package models;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import io.ebean.Finder;
import io.ebean.Model;

@Entity
@Table(name = "intelligent")
public class Intelligent extends Model{
	@Id
	public Integer id;
	public String source = "open IBM";
	public String type = "scan";
	public String description;
	public String time;
	public static Finder<Integer, Intelligent> find = new Finder<>(Intelligent.class);
	
	public String toString() {
		return "{"+"'source:'"+source+",'type:'"+type+",'description:'"+description+",'time:'"+time+"}";
	}
}
