const express=require('express');
const app=express()
const {open}=require('sqlite')
const sqlite3=require('sqlite3')
const cors=require('cors')
const bcrypt=require('bcrypt')
const token=require('jsonwebtoken')
const path=require('path')
app.use(express.json())
app.use(cors())
const dbPath=path.join(__dirname,"hrms.db")

let db=null
async function initializeDb(){

    try{

        db=await open({
            filename:dbPath,
            driver:sqlite3.Database
        
        });
        await db.exec(`
            Create Table if not exists organistation(
            id  integer  PRIMARY KEY autoincrement,
            name Varchar(255) not null,
            created_at Timestamp default current_timestamp
        );`);
            
            await db.exec(`
                Create Table if not exists users(
                id integer PRIMARY KEY autoincrement,
                organistation_id INT References organistation(id),
                name Varchar(255) not null,
                email varchar(255) unique not null,
                password_hash VARCHAR(255) NOT NULL,
                created_at Timestamp default current_timestamp
            );`);
            await db.exec(`
                Create Table if not exists employees(
                id integer PRIMARY KEY AUTOINCREMENT,
                name Varchar(255) not null,
                email varchar(255) not null,
                
                 organistation_id INT References organistation(id)
                );`)
            await db.exec(`
                Create Table if not exists teams(
                id integer PRIMARY KEY AUTOINCREMENT,
                name Varchar(255) not null,
                organistation_id INT References organistation(id)


                );`)
                
            await db.exec(`
                Create Table if not exists employee_team(
                id integer PRIMARY KEY AUTOINCREMENT,
                employee_id INT references employees(id),
                team_id INT references teams(id),
                organistation_id INT References organistation(id)
                );`)
              
                app.listen(3000)
    }
    catch(err){
        console.log('Db error:',err);
        process.exit(1)

    }
}
initializeDb()
app.post("/register",async(req,res)=>{
const {name,email,password,orgName}=req.body
if(!name || !email ||!password ||!orgName) return res.status(404).send("Please enter the fields")
try{
 const query=`Select * from users  where email=?`
 const exist= await db.get(query,[email])
 if(exist){
    res.status(400).send("Email already exist")
 }
let geting=await db.get(`Select * from organistation where name=?`,[orgName])
if(!geting){
    const result=await db.run(`Insert into organistation(name) values(?)`,[orgName])
    geting={id:result.lastID}

}
 const hashing=await bcrypt.hash(password,10)
 const inserting=`Insert Into users(name,email,password_hash,organistation_id) Values(?,?,?,?)`
 await db.run(inserting,[name,email,hashing,geting.id])
 res.status(200).json({message:"Registration SuccessFull"})
 
}catch(e){
    res.status(500).send(`Error in registering ${e}`)
}
})

app.post('/login',async(req,res)=>{
    const{email,password}=req.body;
    if(!email || !password) return res.status(400).send("Requires every fields")
    try{
    const query=await db.get(`Select id,email,password_hash,organistation_id from users where email=?`,[email])
    if(!query) return res.status(400).send("Invalid Email or Password")
    const password_new=await bcrypt.compare(password,query.password_hash)
    if(!password_new) return res.status(400).send("Invalid Email or Password")
    const jsontoken=token.sign({userId:query.id,orgId:query.organistation_id},"My_Secret")
    res.status(200).json({message:"Login Successfull",token:jsontoken})
    }catch(e){
        res.status(500).send(`Error in Login ${e}`)
    }
})
const authentication=async(req,res,next)=>{
    const header=req.headers['authorization']
    if(!header){
      
            return res.status(401).json({ message: "No Authorization header" });
 
    }
    let filter=header.split(" ")[1]
    if(!filter) return res.status(404).send("Invalid Token")
   token.verify(filter, 'My_Secret', (err, payload) => {
        if (err) {
            return res.status(404).send("Invalid Token");
        }
        req.userId = payload.userId;
        req.orgId = payload.orgId;
        // console.log("ORG FROM TOKEN => ", req.orgId);
        
        next();
    });
}
app.get('/employees',authentication,async(req,res)=>{
    try{
    const query=await db.all(`Select * from employees`)
    res.status(200).json(query)
   
}catch(e){
    res.status(400).send(`Can't fetch : ${e}`)
}

})
app.get('/teams',authentication,async(req,res)=>{
    try{
    const query=await db.all(`Select * from teams where organistation_id=?;`, [req.orgId])
    res.status(200).json(query)
   
}catch(e){
    res.status(400).send(`Can't fetch : ${e}`)
}

})
app.post('/teams',authentication,async(req,res)=>{
    
    const {name}=req.body
    try{
        const query=await db.get(`select * from teams where name=?`,[name])
        if(query){
            res.status(400).send("Team is Exist")        
        }
        await db.run(`Insert into teams(name,organistation_id) values(?,?)`,[name,req.orgId])
        res.status(200).send("Successfully Added a Team")

    }catch(e){
        res.status(500).send(`Can't Add the Team :${e}`)
    }
})
app.post('/employees',authentication,async(req,res)=>{
    
    const {name,email}=req.body
    try{
        const query=await db.get(`select * from employees where email=?`,[email])
        if(query){
            res.status(400).send("Employee is Exist")        
        }
        await db.run(`Insert into employees(name,email,organistation_id) values(?,?,?)`,[name,email,req.orgId])
        res.status(200).send("Successfully Added an Employee")

    }catch(e){
        res.status(500).send(`Can't Add the Employee :${e}`)
    }
})
app.delete('/employees/:id',authentication,async(req,res)=>{
    const {id}=req.params
    const requireQuery=`Select * from employees where id=?`
    const isExist=await db.get(requireQuery,[id])
    if(!isExist){
        return res.status(400).send("Employee Not Found")
    }
    try{
   const query= await db.run(`Delete  from employees where id=? `,[id])
   if(!query){
    res.status(400).send("Can't Delete Now")
   }
   res.send("Successfully Deleted")
    }catch(e){
        res.status(500).send(`Can't Delete Now :${e}`)
    }

})
app.delete('/teams/:id',authentication,async(req,res)=>{

    const {id}=req.params
    const requireQuery=`Select * from teams where id=?`
    const isExist=await db.get(requireQuery,[id])
    if(!isExist){
        return res.status(400).send("Team Not Found")
    }
    try{
   const query= await db.run(`Delete  from teams where id=? `,[id])
   if(!query){
    res.status(400).send("Can't Delete Now")
   }
   res.send("Successfully Deleted")
    }catch(e){
        res.status(500).send(`Can't Delete Now :${e}`)
    }

})
app.put('/employees/:id',authentication,async(req,res)=>{
    const {id}=req.params
    const {name,email}=req.body
    const requireQuery=`Select * from employees where id=?`
    const isExist=await db.get(requireQuery,[id])
    if(!isExist){
        return res.status(400).send("Employee Not Found")
    }
    try{
   const query= await db.run(`Update employees set name=?, email=? where id=? `,[name,email,id])
   if(!query){
    res.status(400).send("Can't Update Now")
   }
   res.send("Successfully Updated")
    }catch(e){
        res.status(500).send(`Can't Update Now :${e}`)
    }

})
app.put('/teams/:id',authentication,async(req,res)=>{
    const {id}=req.params
    const {name}=req.body
    const requireQuery=`Select * from teams where id=?`
    const isExist=await db.get(requireQuery,[id])
    if(!isExist){
        return res.status(400).send("Team Not Found")
    }
    try{
   const query= await db.run(`Update teams set name=? where id=? `,[name,id])
   if(!query){
    res.status(400).send("Can't Update Now")
   }
   res.send("Successfully Updated")
    }catch(e){
        res.status(500).send(`Can't Update Now :${e}`)
    }

})
app.post('/assign', authentication, async (req, res) => {
    const { employeeId, teamId } = req.body;

    if (!employeeId || !teamId)
        return res.status(400).send("Employee ID & Team ID required");

    try {
        // check employee
        const emp = await db.get(`SELECT * FROM employees WHERE id = ? AND organistation_id = ?`,
            [employeeId, req.orgId]);

        if (!emp) return res.status(404).send("Employee not found");


        const team = await db.get(`SELECT * FROM teams WHERE id = ? AND organistation_id = ?`,
            [teamId, req.orgId]);

        if (!team) return res.status(404).send("Team not found");

        
        const exists = await db.get(
            `SELECT * FROM employee_team WHERE employee_id = ? AND team_id = ?`,
            [employeeId, teamId]
        );

        if (exists) return res.status(400).send("Already assigned");

        await db.run(
            `INSERT INTO employee_team(employee_id, team_id, organistation_id) VALUES (?, ?, ?)`,
            [employeeId, teamId, req.orgId]
        );

        res.status(200).send("Employee assigned to team");
    } catch (err) {
        res.status(500).send("Error: " + err);
    }
});
app.post('/unassign', authentication, async (req, res) => {
    const { employeeId, teamId } = req.body;

    try {
        const exists = await db.get(
            `SELECT * FROM employee_team WHERE employee_id = ? AND team_id = ?`,
            [employeeId, teamId]
        );

        if (!exists) return res.status(404).send("Assignment not found");

        await db.run(
            `DELETE FROM employee_team WHERE employee_id = ? AND team_id = ?`,
            [employeeId, teamId]
        );

        res.status(200).send("Employee unassigned from team");
    } catch (err) {
        res.status(500).send("Error: " + err);
    }
});
app.get('/employee-team',authentication,async(req,res)=>{
    try{
    const query=await db.all(`Select et.id, e.name as employee_name, t.name as team_name from employee_team et
    join employees e on et.employee_id = e.id
    join teams t on et.team_id = t.id
    where et.organistation_id=?;`, [req.orgId])
    res.status(200).json(query)
    }catch(e){
        res.status(400).send(`Can't fetch : ${e}`)
    }

})

module.exports=app;