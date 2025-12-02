/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package malcommandguard;
import java.io.Serializable;
import java.util.Date;
/**
 *
 * @author User
 */
class User implements Serializable{
    private static final long serialVersionUID = 1L;
    
    private String username;
    private String hashedPassword;
    private String role;
    private Date createdDate;
    
    public User(String username, String hashedPassword, String role) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.role = role;
        this.createdDate = new Date();
    }
    
    public String getUsername() { return username; }
    public String getHashedPassword() { return hashedPassword; }
    public String getRole() { return role; }
    public Date getCreatedDate() { return createdDate; }
    public boolean isAdmin() { return "ADMIN".equals(role); }
    
    @Override
    public String toString() {
        return String.format("User{username='%s', role='%s', created='%s'}", 
                           username, role, createdDate.toString().substring(0, 19));
    }
}

