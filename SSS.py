from numpy import random
import numpy as np
import random
def polynomial(p,x):
    ans=0
    for c in p:
        ans*=x
        ans+=c
    return ans
def spilt_secret(secret,no_of_owners,k,n):
    """
    Given secret is an l bit string
    Secret is shared by n people with threshold of k and no_of_owners must consent

    returns a dictionary with 
    {
        "owner": ["secret1,p1,p2...","secret2,p1,p2..."....] (size is no_of_owners),
        "people": ["x1,y1","x2,y2",...] (size is n-o),
        "k": k,
        "l": l,
        "o": no_of_owners,
    }
    """
    l=len(secret)
    # give half key to owners and half to people
    output={
        "k": k,
        "o": no_of_owners,
        'l':l,
        "owner": [],
        "people": []
    }
    for i in range(no_of_owners):
        output["owner"].append(["",[]])
    for i in range(n-no_of_owners):
        output["people"].append([None,None])
    owner_length=0
    if(no_of_owners!=0):
        owner_length=l//2
        p=np.array(range(0,owner_length))
        random.shuffle(p)
        oi=0
        for i in p:
            output["owner"][oi][0]+=secret[i]
            output["owner"][oi][1].append(i.item())
            oi+=1
            oi%=no_of_owners
    rs=secret[owner_length::]
    nrs=int(rs,base=2)
    rng = np.random.default_rng()
    pc=rng.integers(10000, size=k)
    pc=[i.item() for i in pc]
    pc[-1]=nrs
    x=list(range(1,10000))
    random.shuffle(x)
    x=x[0:(n-no_of_owners)]
    for i,t in enumerate(output["people"]):
        t[0]=x[i]
        t[1]=polynomial(pc,t[0])
    
    for i in range(len(output["people"])):
        output['people'][i]=','.join(str(x) for x in output['people'][i])
    for i in range(len(output["owner"])):
        output['owner'][i]=output['owner'][i][0]+','+','.join(str(x) for x in output['owner'][i][1])
    return output

def get_secret(k_secrets):
    if(k_secrets['k']>len(k_secrets['people'])):
        return None
    if(k_secrets['o']!=len(k_secrets['owner'])):
        return None
    secret=''
    if k_secrets['o']!=0:
        secret=["0"]*(k_secrets['l']//2)
        for s in k_secrets['owner']:
            l=s.split(',')
            for i in range(1,len(l)):
                l[i]=int(l[i])
                secret[l[i]]=l[0][i-1]
        secret=''.join(secret)
    mat=[]
    for s in k_secrets['people']:
        l=s.split(',')
        mat.append([1])
        for i in range(1,k_secrets['k']):
            mat[-1].append(mat[-1][-1]*int(l[0]))
        mat[-1].append(int(l[1]))
    for i in range(k_secrets['k']):
        t=mat[i][i]
        if (t==0):
            for j in range(i+1,len(mat)):
                if mat[j][i]!=0:
                    t=mat[j]
                    mat[j]=mat[i]
                    mat[i]=t
                    break
            t=mat[i][i]
        for j in range(len(mat[0])):
            mat[i][j]//=t
        for j in range(i+1,len(mat[0])-1):
            t=mat[j][i]
            for k in range(len(mat[0])):
                mat[j][k]-=t*mat[i][k]
    for i in range(1,len(mat[0])-1):
        for j in range(0,i):
            t=mat[j][i]
            for k in range(0,len(mat[0])):
                mat[j][k]-=t*mat[i][k]
    ss=bin(int(mat[0][-1]))[2:]
    ss="0"*(k_secrets['l']-len(secret)-len(ss))+ss
    return secret+ss

        
if __name__=='__main__':
    for i in range(1,32):
        key="0101001010101111"*i
        k=200-8
        x=spilt_secret(key,6,k,200)
        x["people"]=x['people'][0:k]
        extracted_key=(get_secret(x))
        if(key==extracted_key):
            print('Success',len(key))
        else:
            print('Fail',key[0:len(key)//2],extracted_key[0:len(extracted_key)//2],key[len(key)//2:],extracted_key[len(extracted_key)//2:],sep='\n')



