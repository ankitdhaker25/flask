import unittest
from app import app, db, User, Customer, Inventory, CustomerPurchase, link_customer_to_user
from werkzeug.security import generate_password_hash

class TestCustomerSync(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_all()

        # Create basic test data
        self.setup_test_data()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def setup_test_data(self):
        # Create shopowner
        self.shopowner = User(
            username="shopowner1",
            email="shop@owner.com",
            password=generate_password_hash("password123"),
            role="shopowner"
        )
        db.session.add(self.shopowner)
        db.session.commit()

        # Create products in shop
        self.product1 = Inventory(
            shop_id=self.shopowner.id,
            item_name="Item A",
            item_price=10.0,
            item_count=100
        )
        self.product2 = Inventory(
            shop_id=self.shopowner.id,
            item_name="Item B",
            item_price=20.0,
            item_count=50
        )
        db.session.add_all([self.product1, self.product2])
        db.session.commit()

        # Create some customer profiles
        self.customer1 = Customer(
            shop_id=self.shopowner.id,
            customer_name="Alice Customer",
            email="alice@customer.com",
            phone="1234567890"
        )
        self.customer2 = Customer(
            shop_id=self.shopowner.id,
            customer_name="Bob Customer",
            email="bob@customer.com",
            phone="0987654321"
        )
        self.customer3 = Customer(
            shop_id=self.shopowner.id,
            customer_name="Duplicate Customer",
            email="duplicate@customer.com"
        )
        self.customer4 = Customer(
            shop_id=self.shopowner.id,
            customer_name="Duplicate Customer 2",
            email="duplicate@customer.com"
        )
        db.session.add_all([self.customer1, self.customer2, self.customer3, self.customer4])
        db.session.commit()

        # Assign purchases
        p1 = CustomerPurchase(customer_id=self.customer1.id, product_id=self.product1.id, quantity=2, price=10.0)
        p2 = CustomerPurchase(customer_id=self.customer2.id, product_id=self.product2.id, quantity=1, price=20.0)
        db.session.add_all([p1, p2])
        db.session.commit()

    def test_auto_linking_exact_match(self):
        # Register user with same email
        user = User(
            username="alice",
            email="alice@customer.com",
            password=generate_password_hash("password123"),
            role="user"
        )
        db.session.add(user)
        db.session.commit()

        # Run linking
        linked = link_customer_to_user(user)
        self.assertTrue(linked)

        # Check in DB
        c = db.session.get(Customer, self.customer1.id)
        self.assertEqual(c.user_id, user.id)

    def test_prevent_auto_linking_multiple_matches(self):
        # Register user with duplicate email
        user = User(
            username="duplicate_user",
            email="duplicate@customer.com",
            password=generate_password_hash("password123"),
            role="user"
        )
        db.session.add(user)
        db.session.commit()

        # Run linking -> should return False and not link automatically
        linked = link_customer_to_user(user)
        self.assertFalse(linked)

        # Verify neither is auto-linked
        c3 = db.session.get(Customer, self.customer3.id)
        c4 = db.session.get(Customer, self.customer4.id)
        self.assertIsNone(c3.user_id)
        self.assertIsNone(c4.user_id)

    def test_user_sees_own_purchases(self):
        # Setup linked user for Alice
        user = User(
            username="alice",
            email="alice@customer.com",
            password=generate_password_hash("password123"),
            role="user"
        )
        db.session.add(user)
        db.session.commit()
        link_customer_to_user(user)

        with self.app as c:
            with c.session_transaction() as sess:
                sess['user'] = user.id

            response = c.get('/my-purchases')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Item A", response.data)
            self.assertNotIn(b"Item B", response.data) # Alice shouldn't see Bob's purchases

    def test_user_cannot_see_another_customer_purchases_api(self):
        # Setup linked user for Alice
        user_alice = User(
            username="alice",
            email="alice@customer.com",
            password=generate_password_hash("password123"),
            role="user"
        )
        db.session.add(user_alice)
        db.session.commit()
        link_customer_to_user(user_alice)

        # Alice should NOT be able to view Bob's purchases via direct API access
        with self.app as c:
            with c.session_transaction() as sess:
                sess['user'] = user_alice.id

            # Accessing Alice's own linked customer id
            response = c.get(f'/my-purchases/{self.customer1.id}')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Item A", response.data)

            # Accessing Bob's customer id
            response2 = c.get(f'/my-purchases/{self.customer2.id}')
            self.assertEqual(response2.status_code, 403) # Forbidden

if __name__ == '__main__':
    unittest.main()
