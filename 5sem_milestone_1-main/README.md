# FoodApp API Documentation

## Overview

The FoodApp API provides endpoints for managing food items and orders. This documentation outlines the available endpoints, their functionalities, and sample requests.

## Getting Started

To start the server, use the command `npm start`. The base URL for the API is `http://localhost:3000`. 
Note that a MongoDB online cluster is used for data storage.

## Authentication

Authentication is required for certain endpoints. Ensure that you are authenticated by accessing http://localhost:3000 before using the API.

## API Endpoints

### 1. Add Food

- **Endpoint:** POST http://localhost:3000/add-food
- **Sample Data:**
```json
{
    "id": "99",
    "name": "Biryani",
    "description": "Delicious Biryani.",
    "price": 100,
    "image": "Biryani.jpg",
    "category": "non-veg"
}
```

### 2. Get All Food

- **Endpoint:** GET http://localhost:3000/get-food
- **Sample Request:** http://localhost:3000/get-food

### 3. Add Order

- **Endpoint:** POST http://localhost:3000/add-order
- **Sample Data:**
```json
{
    "foodId": "1",
    "userId": "user123",
    "orderId": "order123",
    "status": "pending",
    "userAddressId": "address123",
    "paymentMode": "card"
}
```

### 4. Update Order

- **Endpoint:** PUT http://localhost:3000/update-order/{orderId}
- **Sample Request:** http://localhost:3000/update-order/order12
- **Sample Data:**
```json
{
    "status": "completed"
}
```

### 5. Search Food

- **Endpoint:** GET http://localhost:3000/search-food
- **Sample Request:** http://localhost:3000/search-food?keyword=pizza

### 6. Filter Food by Category

- **Endpoint:** GET http://localhost:3000/filter-food
- **Sample Request:** http://localhost:3000/filter-food?category=veg

### 7. Auto-Recommendation

- **Endpoint:** GET http://localhost:3000/auto-recommendation
- **Sample Request:** http://localhost:3000/auto-recommendation?keyword=bir

### 8. Mock Payment

**Sample Data for /add-order Endpoint:**

- **Method:** POST
- **URL:** http://localhost:3000/add-order
- **Headers:**
  - Content-Type: application/json
- **Body:**
```json
{
  "foodId": "sample_food_id",
  "userId": "sample_user_id",
  "userAddressId": "sample_address_id",
  "paymentMode": "credit_card"
}
```

**Sample Data for /mock-payment Endpoint:**

- **Method:** POST
- **URL:** http://localhost:3000/mock-payment
- **Headers:**
  - Content-Type: application/json
- **Body:**
```json
{
    "status": "completed"
}
```
