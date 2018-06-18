package models;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import io.ebean.Finder;
import io.ebean.Model;
@Entity
@Table	(name="ip")
public class IP extends Model{
	@Id
	public Integer id;
	public String ip;
	public String category;
	public double score;
	public String created;
	public static Finder<Integer, IP> find = new Finder<>(IP.class);
	public String toString() {
		return "ip:"+ip+", category:"+category;
	}
}
