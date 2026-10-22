public class shaik_AP25110070437_university {
    public String universityName;
    public String websiteUrl;
    public String contactMobileNumber;
    public int numberOfSchools;
    public int numberOfDepartments;
    public int totalStudentCount;
    public int totalFacultyCount;

   
    public shaik_AP25110070437_university() {
        universityName = "SRM University, AP";
        websiteUrl = "www.srmap.edu.in";
        contactMobileNumber = "+91-863-2343000";
        numberOfSchools = 5; 
        numberOfDepartments = 20; 
        totalStudentCount = 5000; 
        totalFacultyCount = 450; 
    }

    
    public shaik_AP25110070437_university(String name, String url, String contact, int schools, int depts, int students, int faculty) {
        universityName = name;
        websiteUrl = url;
        contactMobileNumber = contact;
        numberOfSchools = schools;
        numberOfDepartments = depts;
        totalStudentCount = students;
        totalFacultyCount = faculty;
    }

    public void displayDetails() {
        System.out.println("--- University Details ---");
        System.out.println("Name: " + universityName);
        System.out.println("Website: " + websiteUrl);
        System.out.println("Contact: " + contactMobileNumber);
        System.out.println("Schools: " + numberOfSchools);
        System.out.println("Departments: " + numberOfDepartments);
        System.out.println("Total Students: " + totalStudentCount);
        System.out.println("Total Faculty: " + totalFacultyCount);
    }

    public static void main(String[] args) {
        shaik_AP25110070437_university myUniversity = new shaik_AP25110070437_university();
        myUniversity.displayDetails();
    }
}