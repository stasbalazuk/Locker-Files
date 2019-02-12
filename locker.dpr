program locker;
{$A-,B-,C+,D+,E-,F-,G+,H+,I+,J+,K-,L+,M-,N+,O+,P+,Q-,R-,S-,T-,U-,V+,W-,X+,Y-,Z1}

uses
  Forms,
  FrFileS in 'FrFileS.pas' {FrmFileSecurity},
  sts in 'sts.pas' {FrmSecProperty};

{$R *.RES}

begin
  Application.Initialize;
  Application.CreateForm(TFrmFileSecurity, FrmFileSecurity);
  Application.Run;
end.
