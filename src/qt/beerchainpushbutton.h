#ifndef BEERCHAINPUSHBUTTON_H
#define BEERCHAINPUSHBUTTON_H
#include <QPushButton>
#include <QStyleOptionButton>
#include <QIcon>

class BeerchainPushButton : public QPushButton
{
public:
    explicit BeerchainPushButton(QWidget * parent = Q_NULLPTR);
    explicit BeerchainPushButton(const QString &text, QWidget *parent = Q_NULLPTR);

protected:
    void paintEvent(QPaintEvent *) Q_DECL_OVERRIDE;

private:
    void updateIcon(QStyleOptionButton &pushbutton);

private:
    bool m_iconCached;
    QIcon m_downIcon;
};

#endif // BEERCHAINPUSHBUTTON_H
