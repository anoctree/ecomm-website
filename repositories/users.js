const fs = require('fs');
const crypto = require('crypto');
const util = require('util');

const scrypt = util.promisify(crypto.scrypt);


class UsersRepository {
    constructor(filename){
        if (!filename){
            throw new Error("Creating a repository reuqires a filename");
        }
        this.filename = filename;

        try{
            fs.accessSync(this.filename);
        } catch {
            fs.writeFileSync(this.filename, '[]');
        }
    }

    async getAll(){
        const contents = await fs.promises.readFile(this.filename, {encoidng: "utf8"});
        return JSON.parse(contents);
    }

    async create(attrs){
        attrs['id'] = this.randomID();
        const salt = crypto.randomBytes(8).toString('hex');
        const buf = await scrypt(attrs.password, salt, 64);
        const record = {
            ...attrs,
            password: `${buf.toString('hex')}.${salt}`
        }
        const records = await this.getAll();
        records.push(record);
        await this.writeAll(records);
        return record;
    }

    async comparePasswords(saved, supplied){
        const [hashed, salt] = saved.split('.');
        const hashedSupplied = await scrypt(supplied, salt, 64);
        return hashedSupplied.toString('hex') === hashed;
    }

    async writeAll(records){
        await fs.promises.writeFile(this.filename, JSON.stringify(records, null, 2));

    }

    randomID(){
        return crypto.randomBytes(4).toString('hex');
    }

    async getOne(id){
        const records = await this.getAll();
        return records.find(record => record.id === id);
    }

    async delete(id){
        const records = await this.getAll();
        const filteredRecords = records.filter(record => record.id !== id);
        await this.writeAll(filteredRecords);
    }

    async update(id, attrs){
        const records = await this.getAll();
        const record = records.find(record => record.id === id);
        if (!record) {
            throw new Error(`Record with id of ${id} not found`);
        }
        Object.assign(record, attrs);
        await this.writeAll(records);
    }

    async getOneBy(filters){
        const records = await this.getAll();
        for (let record of records){
            let found = true;
            for (let key in filters){
                if (record[key] !== filters[key]){
                    found = false;
                }
            }
            if (found){
                return record;
            }
        }
    }
}

module.exports = new UsersRepository('users.json');