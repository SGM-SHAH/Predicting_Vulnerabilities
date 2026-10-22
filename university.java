
public class university {
   String university_name;
   String established_date;
   String university_location;
   String website;
   String email;

   void display_details() {
      System.out.println("University Name: " + university_name);
      System.out.println("Established Date: " + established_date);
      System.out.println("University Location: " + university_location);
      System.out.println("Website: " + website);
      System.out.println("Email: " + email);
   }

   void display_details(String university_name, String established_date,
         String university_location, String website, String email) {
      System.out.println("University Name: " + university_name);
      System.out.println("Established Date: " + established_date);
      System.out.println("University Location: " + university_location);
      System.out.println("Website: " + website);
      System.out.println("Email: " + email);
   }

   static class SRM extends university {
      String faculty;
      String laboratory;
      String renowned_campus;
      String collaboration;

      void display_details() {
         System.out.println("Faculty with International Exposure is: " + faculty);
         System.out.println("Laboratories to enable innovation are: " + laboratory);
         System.out.println("Campus designed by world renowned architects: " + renowned_campus);
         System.out.println("Collaborations with international institutions: " + collaboration);
      }
   }

   public static void main(String[] args) {
      university university_details = new university();
      university_details.university_name = "SRM University-AP";
      university_details.established_date = "2017";
      university_details.university_location = "Andhra Pradesh, India";
      university_details.website = "www.srmap.edu.in";
      university_details.email = "info@srmap.edu.in";
      university_details.display_details();

      SRM srm = new SRM();
      srm.faculty = "Faculty with International Exposure";
      srm.laboratory = "50+ Laboratories to enable innovation";
      srm.renowned_campus = "100 acres";
      srm.collaboration = "International";
      srm.display_details();
   }
}