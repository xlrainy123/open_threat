package models;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import io.ebean.Finder;
import io.ebean.Model;
import io.ebean.annotation.NotNull;

@Entity
@Table(name="search_ip_intelligence")
public class SearchIp extends Model{
	@Id
	public Integer id;
	
	@NotNull
	public String ip;
	
//	@ManyToMany
//	@JoinColumn(name="intelligent")
	public String intelligence;
	public String malware;
	public String event;
	public String domain;
	public String url;
	public Date time;
	
	public boolean equals(Object e) {
		if (e == this) {
			return true;
		}
		if (e instanceof SearchIp) {
			if (((SearchIp)e).ip == this.ip) {
				return true;
			}
		}
		return false;
	} 
	
	public static Finder<Integer, SearchIp> find = new Finder<>(SearchIp.class);
}
