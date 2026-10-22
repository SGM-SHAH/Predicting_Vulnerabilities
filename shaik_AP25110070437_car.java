public class shaik_AP25110070437_car {
    public String make;
    public String model;
    public String chassisNumber;
    public String engineNumber;

    
    public shaik_AP25110070437_car() {
        make = "KIA";
        model = "Sonet";
        chassisNumber = "KNAS123456789";
        engineNumber = "K10B9876543";
    }

    
    public shaik_AP25110070437_car(String make1, String model1, String chassis1, String engine1) {
        make = make1;
        model = model1;
        chassisNumber = chassis1;
        engineNumber = engine1;
    }

    public void displayDetails() {
        System.out.println("--- Vehicle Details ---");
        System.out.println("Make: " + make);
        System.out.println("Model: " + model);
        System.out.println("Chassis Number: " + chassisNumber);
        System.out.println("Engine Number: " + engineNumber);
    }

    public static void main(String[] args) {
       
        shaik_AP25110070437_car defaultCar = new shaik_AP25110070437_car();
        defaultCar.displayDetails();

       
        shaik_AP25110070437_car myCar = new shaik_AP25110070437_car("Toyota", "Fortuner", "MBHF7654321", "2GR-FE9876543");
        myCar.displayDetails();
    }
}
    

