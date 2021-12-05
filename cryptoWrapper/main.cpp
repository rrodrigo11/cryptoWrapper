//
//  main.cpp
//  cryptoWrapper
//
//  Created by Rodrigo Rayas on 04/12/21.
//

#include <iostream>
#include <iomanip>


using namespace std;

int main()
{
    int choice = 1;
    do
    {
        cout << "\n************************ -- MENU -- ***************************************\n";
        cout << "1. Generación y Recuperación de Claves hacia o desde 1 archivo\n";
        cout << "2. Cifrado de Archivos\n";
        cout << "3. Descifrado de Archivos\n";
        cout << "4. Firma de Archivos\n";
        cout << "5. Verificación de Firma de Archivos\n";
        cout << "0. Salir\n";
        cout << "************************ -- END MENU -- ***************************************\n";
        cout << "\nEnter 1, 2, 3, 4, 5 or 0 : ";
        cin >> choice;
        switch (choice)
        {
        case 1:
            cout << "\nGeneración y Recuperación de Claves\n";
            break;
        case 2:
            cout << "\nCifrado de Archivos\n ";
            break;
        case 3:
            cout << "\nDescifrado de Archivos\n ";
            break;
        case 4:
            cout << "\nFirma de Archivos\n";
            break;
        case 5:
            cout << "\nVerificación de firma de Archivos\n";
            break;
        default:
            cout << "\nPlease enter a correct option.\n";
            break;
        }
    }while(choice!=0);
    return 0;
}