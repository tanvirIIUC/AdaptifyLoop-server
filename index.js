const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
// Initialize Supabase client
const port = process.env.PORT || 5000;
const app = express();
// 
// middlewares
app.use(cors());
app.use(express.json());
// Set up multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bebjeyw.mongodb.net/?retryWrites=true&w=majority`;
const uri = process.env.ACCESS_DATABASE_URL;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

function verifyJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.ACCESS_TOKEN, function (err, decoded) {
        if (err) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        req.decoded = decoded;
        next();
    });
}


async function run() {

    try {
        // collections

        const usersCollection = client.db("adaptifyloop").collection("users");
        const paymentsCollection = client.db("adaptifyloop").collection("payments");
        const documentCollection = client.db("adaptifyloop").collection("documents");
       
        app.get('/jwt', async (req, res) => {
            const email = req.query.email;

            const token = jwt.sign({ email }, process.env.ACCESS_TOKEN, { expiresIn: '7d' });
            return res.send({ accessToken: token });

        });

        //get  user
        app.get('/users', async (req, res) => {
            const email = req.query.email;
            const query = { email: email };
            const result = await usersCollection.findOne(query);
            res.send(result);
        });

        app.get('/userStatus/:user_id', async (req, res) => {
            try {
                const user_id = req.params.user_id;
                const userStatus = await paymentsCollection.findOne({ user_id });
                if (!userStatus) {
                    return res.status(404).json({ message: 'User not found' });
                }
                res.status(200).json(userStatus);
            } catch (error) {
                res.status(500).json({ error: 'An error occurred while fetching user status' });
            }
        });

        app.get('/allPaymentDetails', async (req, res) => {
            try {
                // Fetch all payments
                const allPayments = await paymentsCollection.find().toArray();
               

                if (!allPayments || allPayments.length === 0) {
                    return res.status(404).json({ message: 'No payments found' });
                }

                // Extract all user IDs from payments and validate if they are ObjectIds
                const userIds = allPayments.map(payment => {
                    // Check if payment.user_id is a valid ObjectId
                    if (ObjectId.isValid(payment.user_id)) {
                        return new ObjectId(payment.user_id);
                    } else {
                        console.log(`Invalid user_id: ${payment.user_id}`);
                        return null; // Return null for invalid user_id
                    }
                }).filter(id => id !== null); // Remove null values

                // console.log("Valid User IDs:", userIds);

                // Fetch corresponding user details
                const users = await usersCollection.find({ _id: { $in: userIds } }).toArray();
                // console.log('Users:', users);

                // Combine user and payment data
                const combinedDetails = allPayments.map(payment => {
                    const user = users.find(user => user._id.toString() === new ObjectId(payment.user_id).toString());
                    return {
                        ...payment,
                        user,
                    };
                });

                res.status(200).json(combinedDetails);
            } catch (error) {
                console.error('Error fetching payment details:', error.message || error);
                res.status(500).json({ error: 'An error occurred while fetching payment details' });
            }
        });

        app.put('/userStatus/:user_id', async (req, res) => {
            try {
              const user_id = req.params.user_id;
              const { status } = req.body; // Extract status from the body
          
              if (!status) {
                return res.status(400).json({ message: 'Status is required' });
              }
          
              // Find the payment based on user_id
              const userStatus = await paymentsCollection.findOne({ user_id });
          
              if (!userStatus) {
                return res.status(404).json({ message: 'User not found' });
              }
          
              // Update the status
              const updatedPayment = await paymentsCollection.updateOne(
                { user_id },
                { $set: { status: status } }
              );
          
              if (updatedPayment.matchedCount === 0) {
                return res.status(404).json({ message: 'Payment not found for the user' });
              }
          
              res.status(200).json({ message: 'Payment status updated successfully', updatedPayment });
            } catch (error) {
              res.status(500).json({ error: 'An error occurred while updating user status' });
            }
          });

        // add users 
        app.post('/users', async (req, res) => {
            const user = req.body;

            // Validate required fields (remove strict email checks)
            if (!user.name || !user.email || !user.password) {
                return res.status(400).send({ message: 'Name, email, and password are required' });
            }

            // Check if the email already exists
            const query = { email: user.email };
            const userExists = await usersCollection.findOne(query);
            if (userExists) {
                return res.status(400).send({ message: 'User already exists' });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(user.password, 10);

            // Save user to the database
            const newUser = {
                ...user,
                password: hashedPassword,
                role: user.role || 'user', // Default to 'user'
                created_at: new Date(),
            };

            try {
                const result = await usersCollection.insertOne(newUser);
                res.status(201).send(result);
            } catch (error) {
                console.error('Error saving user:', error);
                res.status(500).send({ message: 'Internal Server Error', error: error.message });
            }
        });
        app.post('/uploadDocument', async (req, res) => {
            const document = req.body;
        
            // Validate required fields
            if (!document.user_id || !document.file_url) {
                return res.status(400).send({ message: "user_id and file_url are required" });
            }
        
            try {
                // Check if a document with the same file_url already exists
                const query = { file_url: document.file_url };
                const documentExists = await documentCollection.findOne(query);
                if (documentExists) {
                    return res.status(400).send({ message: "Document already exists with the same file_url" });
                }
        
                // Create a new document object
                const newDocument = {
                    user_id: document.user_id,
                    file_url: document.file_url,
                    status: document.status || "Pending", // Default status is 'pending'
                    uploaded_at: new Date(), // Current timestamp
                };
        
                // Save the document to the `document` collection
                const result = await documentCollection.insertOne(newDocument);
        
                res.status(201).send({
                    message: "Document uploaded successfully",
                    document: result.ops[0], // Send back the newly created document
                });
            } catch (error) {
                console.error("Error saving document:", error);
                res.status(500).send({ message: "Internal Server Error", error: error.message });
            }
        });
        app.get('/documentStatus/:user_id', async (req, res) => {
            try {
                const user_id = req.params.user_id;
                const userStatus = await documentCollection.findOne({ user_id });
                if (!userStatus) {
                    return res.status(404).json({ message: 'User not found' });
                }
                res.status(200).json(userStatus);
            } catch (error) {
                res.status(500).json({ error: 'An error occurred while fetching user status' });
            }
        });
        app.get('/allDocumentDetails', async (req, res) => {
            try {
                // Fetch all document
                const allDocuments = await documentCollection.find().toArray();
               

                if (!allDocuments || allDocuments.length === 0) {
                    return res.status(404).json({ message: 'No document found' });
                }

                // Extract all user IDs from document and validate if they are ObjectIds
                const userIds = allDocuments.map(document => {
                    // Check if document.user_id is a valid ObjectId
                    if (ObjectId.isValid(document.user_id)) {
                        return new ObjectId(document.user_id);
                    } else {
                        // console.log(`Invalid user_id: ${document.user_id}`);
                        return null; // Return null for invalid user_id
                    }
                }).filter(id => id !== null); // Remove null values

                // Fetch corresponding user details
                const users = await usersCollection.find({ _id: { $in: userIds } }).toArray();
                // Combine user and document data
                const combinedDetails = allDocuments.map(document => {
                    const user = users.find(user => user._id.toString() === new ObjectId(document.user_id).toString());
                    return {
                        ...document,
                        user,
                    };
                });

                res.status(200).json(combinedDetails);
            } catch (error) {
                console.error('Error fetching payment details:', error.message || error);
                res.status(500).json({ error: 'An error occurred while fetching payment details' });
            }
        });
        app.put('/updateDocumentStatus/:user_id', async (req, res) => {
            try {
              const user_id = req.params.user_id;
              const { status } = req.body; // Extract status from the body
          
              if (!status) {
                return res.status(400).json({ message: 'Status is required' });
              }
          
              // Find the payment based on user_id
              const userStatus = await documentCollection.findOne({ user_id });
          
              if (!userStatus) {
                return res.status(404).json({ message: 'User not found' });
              }
          
              // Update the status
              const updatedDocumentStatus = await documentCollection.updateOne(
                { user_id },
                { $set: { status: status } }
              );
          
              if (updatedDocumentStatus.matchedCount === 0) {
                return res.status(404).json({ message: 'Document not found for the user' });
              }
          
              res.status(200).json({ message: 'Document status updated successfully', updatedDocumentStatus });
            } catch (error) {
              res.status(500).json({ error: 'An error occurred while updating user status' });
            }
          });

        app.post('/create-payment-intent', async (req, res) => {
            const { amount, title, user_id,email } = req.body;

            if (!amount || !title || !user_id || !email) {
                return res.status(400).send({ error: 'Missing required fields' });
            }

            try {
                const paymentIntent = await stripe.paymentIntents.create({
                    amount,
                    currency: 'usd',
                    metadata: { title, user_id },
                });

                // Save payment in the database
                const payment = {
                    title,
                    amount,
                    user_id,
                    email,
                    created_at: new Date(),
                    status: 'Pending',
                };
                const result = await paymentsCollection.insertOne(payment);

                res.status(200).send({
                    clientSecret: paymentIntent.client_secret,
                    paymentId: result.insertedId,
                });
            } catch (error) {
                console.error('Error creating payment intent:', error.message);
                res.status(500).send({ error: error.message });
            }
        });

        // Webhook to handle payment updates
        app.post('/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
            const sig = req.headers['stripe-signature'];
            const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

            let event;
            try {
                event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
            } catch (err) {
                console.error('Webhook signature verification failed.', err.message);
                return res.status(400).send(`Webhook Error: ${err.message}`);
            }

            if (event.type === 'payment_intent.succeeded') {
                const paymentIntent = event.data.object;
                const paymentId = paymentIntent.metadata.paymentId;

                // Update the payment status in the database
                await Payment.findOneAndUpdate({ id: paymentId }, { status: 'succeeded' });
            }

            res.status(200).send();
        });

        app.post("/uploadDocument", async (req, res) => {
            const document = req.body;
            // Validate required fields
            if (!document.user_id || !document.file_url) {
                return res.status(400).send({ message: "user_id and file_url are required" });
            }
        
            try {
                // Check if a document with the same file_url already exists
                const query = { file_url: document.file_url };
                const documentExists = await documentCollection.findOne(query);
                if (documentExists) {
                    return res.status(400).send({ message: "Document already exists with the same file_url" });
                }
        
                // Create a new document object
                const newDocument = {
                    id: uuidv4(), // Generate a unique UUID
                    user_id: document.user_id,
                    file_url: document.file_url,
                    status: document.status || "pending", // Default status is 'pending'
                    uploaded_at: new Date(), // Current timestamp
                };
        
                // Save the document to the `document` collection
                const result = await documentCollection.insertOne(newDocument);
        
                res.status(201).send({
                    message: "Document uploaded successfully",
                    document: result.ops[0], // Send back the newly created document
                });
            } catch (error) {
                console.error("Error saving document:", error);
                res.status(500).send({ message: "Internal Server Error", error: error.message });
            }
        });
      
        
          
     
    }
    finally {

    }

}

run().catch(err => console.error(err));


app.get('/', async (req, res) => {
    res.send('adaptifyloop server is running')
});

app.listen(port, () => {
    console.log(`adaptifyloop Server is running on ${[port]}`);
});