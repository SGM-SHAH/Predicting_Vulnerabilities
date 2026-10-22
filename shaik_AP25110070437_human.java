public class shaik_AP25110070437_human {
    public String name;
    public double height;
    public double weight;
    public String gender;
    private String identity_details;

    // Default Constructor
    shaik_AP25110070437_human() {
        name = "Shaik Ghouse Mohiddin Shah";
        height = 5.8;
        weight = 70.0;
        gender = "Male";
        identity_details = "B.Tech CSE-AIML Student at SRM University AP";
    }

    // Parameterized Constructor (Constructor Overloading)
    shaik_AP25110070437_human(String name1, double height1, double weight1, String gender1, String identity_details1) {
        name = name1;
        height = height1;
        weight = weight1;
        gender = gender1;
        identity_details = identity_details1;
    }

    // Method to display all details
    void shaik_AP25110070437_display_details() {
        System.out.println("The Name is " + name);
        System.out.println("The Height is " + height);
        System.out.println("The Weight is " + weight);
        System.out.println("The Gender is " + gender);
    }

    // Overloaded Method to display specific details (Method Overloading)
    void display_details(String name, String identity) {
        System.out.println("The Name is " + name);
        System.out.println("The Identity is " + identity);
    }

    public static void main(String[] args) {
        System.out.println("Welcome to constructor");
        
        // Creating object using parameterized constructor with your details
        shaik_AP25110070437_human shaik = new shaik_AP25110070437_human(
            "Shaik Ghouse Mohiddin Shah", 
            5.10, 
            68.5, 
            "Male", 
            "Reg No: AP25110070437, B.Tech CSE-AIML Student"
        );
        
        shaik.shaik_AP25110070437_display_details();
        shaik.display_details(shaik.name, shaik.identity_details);
    }
}