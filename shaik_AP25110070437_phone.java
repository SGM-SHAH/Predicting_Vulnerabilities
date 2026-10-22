public class shaik_AP25110070437_phone {
    public String brand;
    public String model;
    public double screenHeight;
    public double screenWidth;
    public double weight;
    public String usbPortType;

    
    public shaik_AP25110070437_phone() {
        brand = "Nothing";
        model = "Phone 3a";
        screenHeight = 6.7;
        screenWidth = 3.0;
        weight = 190.0;
        usbPortType = "Type-C";
    }

    
    public shaik_AP25110070437_phone(String b, String m, double sh, double sw, double w, String usb) {
        brand = b;
        model = m;
        screenHeight = sh;
        screenWidth = sw;
        weight = w;
        usbPortType = usb;
    }

    public void displayDetails() {
        System.out.println("--- Smartphone Details ---");
        System.out.println("Brand: " + brand);
        System.out.println("Model: " + model);
        System.out.println("Screen Dimensions: " + screenHeight + "\" x " + screenWidth + "\"");
        System.out.println("Weight: " + weight + " grams");
        System.out.println("USB Port Type: " + usbPortType);
    }

    public static void main(String[] args) {
        shaik_AP25110070437_phone myPhone = new shaik_AP25110070437_phone();
        myPhone.displayDetails();
    }
}
    

